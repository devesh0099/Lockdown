import logging
from platform.windows_firewall import WindowsFirewall
from core.state_manager import StateManager
from core.dns_interceptor import DNSInterceptor 
from platform.windows_dns import WindowsDNS
from monitoring.interface_monitor import InterfaceMonitor
from core.rule_cache import RuleCache


logger = logging.getLogger(__name__)

class FirewallManager:
    def __init__(self, rule_ttl: int = 300):
        self.backend = WindowsFirewall()
        self.state_manager = StateManager()
        self.dns_interceptor = None
        self.dns_config = WindowsDNS()
        self.interface_monitor = None
        self.rule_cache = RuleCache(default_ttl=rule_ttl)

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
        
        if not self.rule_cache.start_cleanup_thread(on_rule_expired=self._on_rule_expired):
            logger.warning("Rule cleanup thread failed to start (non-critical)")
      

        logger.info("LOCKDOWN ACTIVE WITH DNS FILTERING")
        logger.info(f"Allowed domains: {whitelist_domains}")
        logger.info(f"   Interface Monitoring: {'Enabled' if self.interface_monitor else 'Disabled'}")
        return True

    def _on_dns_resolved(self, domain: str, ip: str):
        logger.info(f"Whitelisting {ip} for {domain}")
        rule_name_https = self.backend.add_allow_rule(ip, port=443, protocol="tcp")
        rule_name_http = self.backend.add_allow_rule(ip, port=80, protocol="tcp")
        self.rule_cache.add_rule(
            rule_name=rule_name_https,
            ip=ip,
            port=443,
            protocol="TCP",
            domain=domain,
            ttl=self.rule_cache.default_ttl
        )

        self.rule_cache.add_rule(
            rule_name=rule_name_http,
            ip=ip,
            port=80,
            protocol="TCP",
            domain=domain,
            ttl=self.rule_cache.default_ttl
        )

    def _on_rule_expired(self, rule_name: str, ip: str, port: int, protocol: str):
            logger.info(f"Rule expired: {ip}:{port}/{protocol} - Removing from firewall")
            self.backend.delete_rule_by_name(rule_name)

    def _on_new_interface(self, interface_name: str):
        logger.warning(f"NEW NETWORK INTERFACE DETECTED: {interface_name}")
        logger.warning(f"Firewall rules automatically apply to this interface")
        logger.warning(f"If this is USB tethering, it will be blocked")
    

    def allow_ip(self, ip:str, port: int = 443, protocol:str = "tcp") -> bool:
        if not self.backend.is_active:
            return False

        rule_name = self.backend.add_allow_rule(ip, port, protocol)
        if rule_name:
            self.rule_cache.add_rule(
                rule_name=rule_name,
                ip=ip,
                port=port,
                protocol=protocol.upper(),
                ttl=None
            )
            return True
        return False
    
    def revoke_ip(self, ip:str, port: int = 443, protocol: str = "tcp") -> bool:
        success = self.backend.delete_rule_by_ip(ip, port, protocol)
        
        if success:
            rule_name = f"{self.backend.GROUP_NAME}_{ip.replace('.', '_')}_{port}_{protocol.upper()}"
            self.rule_cache.delete_rule(rule_name)
        
        return success
    
    def disable_lockdown(self) -> bool:
        logger.info("DISABLING LOCKDOWN")
        
        self.rule_cache.stop_cleanup_thread()
        
        self.rule_cache.clear_all()

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
        cached_rules = self.rule_cache.get_all_rules()
        
        result = []
        for rule in cached_rules:
            time_left = rule['time_left_seconds']
            minutes_left = time_left // 60
            seconds_left = time_left % 60
            
            domain_info = f" ({rule['domain']})" if rule['domain'] else ""
            result.append(
                f"{rule['ip']}:{rule['port']}/{rule['protocol']}{domain_info} "
                f"[expires in {minutes_left}m {seconds_left}s]"
            )
        
        return result
    
    def get_cache_stats(self) -> dict:
        return self.rule_cache.get_stats()
    
    def status(self) -> dict:
        cache_stats = self.get_cache_stats()

        return {
            "active": self.backend.is_active,
            "dns_interceptor": self.dns_interceptor is not None and self.dns_interceptor.running,
            "interface_monitor": self.interface_monitor is not None and self.interface_monitor.running,
            "rule_ttl": self.rule_cache.default_ttl,
            "whitelisted_ips": self.get_whitelisted_ips(),
            "cache_stats": cache_stats
        }