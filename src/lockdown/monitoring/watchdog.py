import subprocess
import threading
import time
import logging
import re
from typing import Optional, Callable

logger = logging.getLogger(__name__)

class FirewallWatchdog:
     
    def __init__(self, group_name: str, on_tampering_detected: Optional[Callable] = None):
        self.group_name = group_name
        self.on_tampering_detected = on_tampering_detected
        self.running = False
        self.thread = None
        self.expected_rules = set()
        self.last_event_id = None

    def start(self) -> bool:
        try:
            # Get initial rule snapshot
            self._update_expected_rules()
            
            logger.info(f"Watchdog started. Protecting {len(self.expected_rules)} rules")
            logger.info(f"Monitoring for unauthorized firewall changes")
            
            self.running = True
            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start watchdog: {e}")
            return False

    def stop(self):
        logger.info("Stopping watchdog")
        self.running = False
        
        if self.thread:
            self.thread.join(timeout=3)
        
        logger.info("Watchdog stopped")

    def register_rule(self, rule_name: str):
        self.expected_rules.add(rule_name)
        logger.debug(f"Watchdog now protecting: {rule_name}")

    def unregister_rule(self, rule_name: str):
        self.expected_rules.discard(rule_name)
        logger.debug(f"Watchdog stopped protecting: {rule_name}")

    def _update_expected_rules(self):
        try:
            result = subprocess.run(
                f'netsh advfirewall firewall show rule name=all | findstr /C:"Rule Name:"',
                shell=True,
                capture_output=True,
                text=True
            )
            
            self.expected_rules.clear()
            
            for line in result.stdout.splitlines():
                if self.group_name in line:
                    # Extract rule name
                    match = re.search(r'Rule Name:\s+(.+)', line)
                    if match:
                        rule_name = match.group(1).strip()
                        self.expected_rules.add(rule_name)
            
            logger.debug(f"Updated expected rules: {len(self.expected_rules)} rules tracked")
            
        except Exception as e:
            logger.error(f"Failed to update expected rules: {e}")

    def _monitor_loop(self):
        while self.running:
            try:
                self._check_rule_integrity()
                
                self._check_for_unauthorized_rules()
                
                if int(time.time()) % 10 == 0:
                    self._check_event_log()
                
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Error in watchdog loop: {e}")
                time.sleep(5)

    def _check_rule_integrity(self):
        try:
            result = subprocess.run(
                f'netsh advfirewall firewall show rule name=all',
                shell=True,
                capture_output=True,
                text=True
            )
            
            output = result.stdout
            
            for rule_name in list(self.expected_rules):
                if f'Rule Name:                            {rule_name}' not in output:
                    logger.error(f"🚨 TAMPERING DETECTED: Rule deleted by external process!")
                    logger.error(f"   Deleted rule: {rule_name}")
                    
                    if self.on_tampering_detected:
                        self.on_tampering_detected("rule_deleted", {"rule_name": rule_name})
                    
                    self.expected_rules.discard(rule_name)
            
        except Exception as e:
            logger.error(f"Failed to check rule integrity: {e}")

    def _check_for_unauthorized_rules(self):
        try:
            result = subprocess.run(
                'netsh advfirewall firewall show rule name=all dir=out',
                shell=True,
                capture_output=True,
                text=True
            )
            
            lines = result.stdout.splitlines()
            current_rule = None
            action = None
            
            for line in lines:
                line = line.strip()
                
                if line.startswith('Rule Name:'):
                    current_rule = line.replace('Rule Name:', '').strip()
                    action = None
                
                elif line.startswith('Action:'):
                    action = line.replace('Action:', '').strip().lower()
                    
                    if action == 'allow' and current_rule:
                        if self.group_name not in current_rule:
                            if not self._is_system_rule(current_rule):
                                logger.warning(f"SUSPICIOUS RULE DETECTED!")
                                logger.warning(f"Rule: {current_rule}")
                                logger.warning(f"Action: ALLOW (not created by lockdown)")
                                
                                if self.on_tampering_detected:
                                    self.on_tampering_detected("unauthorized_rule", {
                                        "rule_name": current_rule,
                                        "action": action
                                    })
            
        except Exception as e:
            logger.error(f"Failed to check for unauthorized rules: {e}")

    def _check_event_log(self):
        try:
            cmd = (
                'powershell -Command "'
                'Get-WinEvent -FilterHashtable @{LogName=\'Security\'; ID=4946,4947,4948} '
                '-MaxEvents 5 -ErrorAction SilentlyContinue | '
                'Select-Object TimeCreated, Id, Message | '
                'ConvertTo-Json"'
            )
            
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip():
                import json
                events = json.loads(result.stdout)
                
                if not isinstance(events, list):
                    events = [events]
                
                for event in events:
                    event_id = event.get('Id')
                    message = event.get('Message', '')
                    
                    event_signature = f"{event.get('TimeCreated')}_{event_id}"
                    if event_signature == self.last_event_id:
                        continue
                    
                    self.last_event_id = event_signature
                    
                    if self.group_name in message:
                        continue  # It's our legitimate change
                    
                    event_types = {
                        4946: "Rule Added",
                        4947: "Rule Modified",
                        4948: "Rule Deleted"
                    }
                    
                    logger.warning(f"EVENT LOG TAMPERING: {event_types.get(event_id, 'Unknown')}")
                    logger.warning(f"Time: {event.get('TimeCreated')}")
                    
                    if self.on_tampering_detected:
                        self.on_tampering_detected("event_log_change", {
                            "event_id": event_id,
                            "type": event_types.get(event_id, 'Unknown')
                        })
        
        except subprocess.TimeoutExpired:
            logger.debug("Event log query timed out (normal if no events)")
        except Exception as e:
            logger.debug(f"Event log check failed: {e}")

    def _is_system_rule(self, rule_name: str) -> bool:
        system_prefixes = [
            "Core Networking",
            "Network Discovery",
            "File and Printer Sharing",
            "Remote Desktop",
            "Windows Remote Management",
            "@"
        ]
        
        for prefix in system_prefixes:
            if rule_name.startswith(prefix):
                return True
        
        return False
