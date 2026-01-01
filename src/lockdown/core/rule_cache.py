import sqlite3
import threading
import time
import logging
from pathlib import Path
from typing import List, Tuple, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class RuleCache:
    def __init__(self, db_path: Optional[Path] = None, default_ttl: int = 1200): # 20 minutes or 1200 seconds
        if db_path is None:
            db_path = Path.home() / ".lockdown" / "rules.db"
        
        self.db_path = db_path
        self.default_ttl = default_ttl
        self.cleanup_thread = None
        self.running = False
        
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._init_db()
    
    def _init_db(self):
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS firewall_rules (
                    rule_name TEXT PRIMARY KEY,
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    domain TEXT,
                    added_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                )
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_expires_at 
                ON firewall_rules(expires_at)
            """)
            
            conn.commit()
            conn.close()
            
            logger.info(f"Rule cache database initialized: {self.db_path}")
            
        except Exception as e:
            logger.error(f"Failed to initialize rule cache database: {e}")
            raise
    
    def add_rule(self, rule_name: str, ip: str, port: int, protocol: str, 
                 domain: str = None, ttl: int = None) -> bool:
        try:
            if ttl is None:
                ttl = self.default_ttl
            
            now = int(time.time())
            expires_at = now + ttl
            
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO firewall_rules 
                (rule_name, ip, port, protocol, domain, added_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (rule_name, ip, port, protocol, domain, now, expires_at))
            
            conn.commit()
            conn.close()
            
            expires_in = ttl // 60  # Convert to minutes for logging
            logger.debug(f"Added rule to cache: {ip}:{port} (expires in {expires_in}m)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add rule to cache: {e}")
            return False
    
    def get_expired_rules(self) -> List[Tuple[str, str, int, str]]:
        try:
            now = int(time.time())
            
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT rule_name, ip, port, protocol, domain
                FROM firewall_rules
                WHERE expires_at <= ?
            """, (now,))
            
            expired = cursor.fetchall()
            conn.close()
            
            return expired
            
        except Exception as e:
            logger.error(f"Failed to query expired rules: {e}")
            return []
    
    def delete_rule(self, rule_name: str) -> bool:
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM firewall_rules WHERE rule_name = ?", (rule_name,))
            
            conn.commit()
            conn.close()
            
            logger.debug(f"Deleted rule from cache: {rule_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete rule from cache: {e}")
            return False
    
    def get_all_rules(self) -> List[dict]:
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT rule_name, ip, port, protocol, domain, added_at, expires_at
                FROM firewall_rules
            """)
            
            rows = cursor.fetchall()
            conn.close()
            
            now = int(time.time())
            rules = []
            
            for row in rows:
                rule_name, ip, port, protocol, domain, added_at, expires_at = row
                time_left = expires_at - now
                
                rules.append({
                    "rule_name": rule_name,
                    "ip": ip,
                    "port": port,
                    "protocol": protocol,
                    "domain": domain,
                    "added_at": datetime.fromtimestamp(added_at).isoformat(),
                    "expires_at": datetime.fromtimestamp(expires_at).isoformat(),
                    "time_left_seconds": max(0, time_left)
                })
            
            return rules
            
        except Exception as e:
            logger.error(f"Failed to get all rules: {e}")
            return []
    
    def clear_all(self) -> bool:
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM firewall_rules")
            
            conn.commit()
            conn.close()
            
            logger.info("Rule cache cleared")
            return True
            
        except Exception as e:
            logger.error(f"Failed to clear rule cache: {e}")
            return False
    
    def start_cleanup_thread(self, on_rule_expired=None) -> bool:
        try:
            self.running = True
            self.cleanup_thread = threading.Thread(
                target=self._cleanup_loop,
                args=(on_rule_expired,),
                daemon=True
            )
            self.cleanup_thread.start()
            
            logger.info("Rule cleanup thread started (checks every 60s)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start cleanup thread: {e}")
            return False
    
    def stop_cleanup_thread(self):
        logger.info("Stopping rule cleanup thread...")
        self.running = False
        
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=3)
        
        logger.info("Rule cleanup thread stopped")
    
    def _cleanup_loop(self, on_rule_expired):
        logger.info("Rule cleanup loop started")
        
        while self.running:
            try:
                expired = self.get_expired_rules()
                
                if expired:
                    logger.info(f"Found {len(expired)} expired rule(s)")
                    
                    for rule_name, ip, port, protocol, domain in expired:
                        if on_rule_expired:
                            on_rule_expired(rule_name, ip, port, protocol)
                        
                        self.delete_rule(rule_name)
                        
                        domain_info = f" ({domain})" if domain else ""
                        logger.info(f"Expired: {ip}:{port}/{protocol}{domain_info}")
                
                # Wait 60 seconds before next check
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
                time.sleep(60)
    
    def get_stats(self) -> dict:
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM firewall_rules")
            total_rules = cursor.fetchone()[0]
            
            now = int(time.time())
            cursor.execute("SELECT COUNT(*) FROM firewall_rules WHERE expires_at <= ?", (now,))
            expired_rules = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                "total_rules": total_rules,
                "active_rules": total_rules - expired_rules,
                "expired_rules": expired_rules
            }
            
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {"total_rules": 0, "active_rules": 0, "expired_rules": 0}
