import logging
from typing import Optional
from platform.windows_firewall import WindowsFirewall
from core.state_manager import StateManager
from core.dns_interceptor import DNSInterceptor 
from platform.windows_dns import WindowsDNS
from monitoring.interface_monitor import InterfaceMonitor

logger = logging.getLogger(__name__)

class FirewallManager:
    def __init__(self):
        self.backend = WindowsFirewall()
        self.state_manager = StateManager()
        self.dns_interceptor = None
        self.dns_config = WindowsDNS()
        self.interface_monitor = None

    def enable_lockdown(self, whitelist_domains: list = None) -> bool:
        logger.info("ENABLING NETWORK LOCKDOWN")
        
        if whitelist_domains is None:
            whitelist_domains = [r".*\.codeforces\.com$", r"codeforces\.com$"]
        
        if not self.state_manager.capture_state():
            logger.error("Failed to capture system state, aborting")
            return False
        
        self.interface_monitor = InterfaceMonitor(
            on_new_interface=self._on_new_interface
        )
        
        if not self.interface_monitor.start():
            logger.warning("Interface monitor failed to start (non-critical)")

        self.dns_interceptor = DNSInterceptor(
            whitelist_patterns=whitelist_domains,
            on_ip_resolved=self._on_dns_resolved
        )

        if not self.dns_interceptor.start():
            logger.error("Failed to start DNS interceptor")
            if self.interface_monitor:
                self.interface_monitor.stop()
            self.state_manager.restore_state()
            return False
        
        if not self.dns_config.set_dns_to_localhost():
            logger.error("Failed to configure DNS")
            self.dns_config.restore_dns_to_dhcp()
            self.dns_interceptor.stop()
            if self.interface_monitor:
                self.interface_monitor.stop()
            self.state_manager.restore_state()
            return False

        if not self.backend.initialize():
            self.dns_config.restore_dns_to_dhcp()
            self.dns_interceptor.stop()
            if self.interface_monitor:
                self.interface_monitor.stop()
            self.state_manager.restore_state()
            return False
        
        logger.info("LOCKDOWN ACTIVE WITH DNS FILTERING")
        logger.info(f"Allowed domains: {whitelist_domains}")
        logger.info(f"   Interface Monitoring: {'Enabled' if self.interface_monitor else 'Disabled'}")
        return True

    def _on_dns_resolved(self, domain: str, ip: str):
        logger.info(f"Whitelisting {ip} for {domain}")
        self.backend.add_allow_rule(ip, port=443, protocol="tcp")
        self.backend.add_allow_rule(ip, port=80, protocol="tcp")

    def _on_new_interface(self, interface_name: str):
        logger.warning(f"NEW NETWORK INTERFACE DETECTED: {interface_name}")
        logger.warning(f"Firewall rules automatically apply to this interface")
        logger.warning(f"If this is USB tethering, it will be blocked")
    

    def allow_ip(self, ip:str, port: int = 443, protocol:str = "tcp") -> bool:
        if not self.backend.is_active:
            return False

        rule_name = self.backend.add_allow_rule(ip, port, protocol)
        return rule_name is not None
    
    def revoke_ip(self, ip:str, port: int = 443, protocol: str = "tcp") -> bool:
        return self.backend.delete_rule_by_ip(ip, port, protocol)
    
    def disable_lockdown(self) -> bool:
        logger.info("DISABLING LOCKDOWN")

        if self.interface_monitor:
            self.interface_monitor.stop()
            
        if self.dns_interceptor:
            self.dns_interceptor.stop()

        self.dns_config.restore_dns_to_dhcp()

        success = self.state_manager.restore_state()
        
        if success:
            self.backend.is_active = False
            logger.info("System fully restored")
        
        return success
    
    def get_whitelisted_ips(self) -> list:
        rules = self.backend.get_active_rules()
        result = []
        
        for r in rules:
            if r.get('type') in ['loopback', 'upstream_dns']:
                continue
            
            ip = r.get('ip', 'unknown')
            port = r.get('port', '?')
            protocol = r.get('protocol', 'TCP')
            
            result.append(f"{ip}:{port}/{protocol}")
        
        return result

    
    def status(self) -> dict:
        return {
            "active": self.backend.is_active,
            "dns_interceptor": self.dns_interceptor is not None and self.dns_interceptor.running,
            "whitelisted_ips": self.get_whitelisted_ips(),
            "rule_count": len(self.backend.rules)
        }