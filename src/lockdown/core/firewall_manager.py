import logging
from typing import Optional
from platform.windows_firewall import WindowsFirewall
from core.state_manager import StateManager

logger = logging.getLogger(__name__)

class FirewallManager:
    def __init__(self):
        self.backend = WindowsFirewall()
        self.state_manager = StateManager()

    def enable_lockdown(self) -> bool:
        logger.info("ENABLING NETWORK LOCKDOWN")

        if not self.state_manager.capture_state():
            logger.error("Failed to capture system state, aborting")
            return False
        
        if not self.backend.initialize():
            self.state_manager.restore_state()
            return False
        
    def allow_ip(self, ip:str, port: int = 443, protocol:str = "tcp") -> bool:
        if not self.backend.is_active:
            return False

        rule_name = self.backend.add_allow_rule(ip, port, protocol)
        return rule_name is not None
    
    def revoke_ip(self, ip:str, port: int = 443, protocol: str = "tcp") -> bool:
        return self.backend.delete_rule_by_ip(ip, port, protocol)
    
    def revoke_ip(self, ip: str, port: int = 443, protocol: str = "tcp") -> bool:
        return self.backend.delete_rule_by_ip(ip, port, protocol)
    
    def disable_lockdown(self) -> bool:
        logger.info("DISABLING LOCKDOWN")
        
        success = self.state_manager.restore_state()
        
        if success:
            self.backend.is_active = False
            logger.info("Lockdown disabled")
        else:
            logger.error(" Error in Restoration")
        
        return success
    
    def get_whitelisted_ips(self) -> list:
        rules = self.backend.get_active_rules()
        return [
            f"{r['ip']}:{r['port']}/{r['protocol']}"
            for r in rules
        ]
    
    def status(self) -> dict:
        return {
            "active": self.backend.is_active,
            "whitelisted_ips": self.get_whitelisted_ips(),
            "rule_count": len(self.backend.rules)
        }