import logging
import subprocess
from platform.windows_firewall import WindowsFirewall
from core.state_manager import StateManager
from core.dns_interceptor import DNSInterceptor 
from platform.windows_dns import WindowsDNS
from monitoring.interface_monitor import InterfaceMonitor
from core.rule_cache import RuleCache
from monitoring.watchdog import FirewallWatchdog
from security.state_flush import StateFlush


logger = logging.getLogger(__name__)

class FirewallManager:
    def __init__(self, rule_ttl: int = 1200):
        self.backend = WindowsFirewall()
        self.state_manager = StateManager()
        self.dns_interceptor = None
        self.dns_config = WindowsDNS()
        self.interface_monitor = None
        self.rule_cache = RuleCache(default_ttl=rule_ttl)
        self.watchdog = None


    def enable_lockdown(self, whitelist_domains: list = None, flush_initial_state: bool = True) -> bool:
        logger.info("ENABLING NETWORK LOCKDOWN")
        
        if whitelist_domains is None:
            whitelist_domains = [r".*\.codeforces\.com$", r"codeforces\.com$"]
        
        if not self.state_manager.capture_state():
            logger.error("Failed to capture system state, aborting")
            return False
        
        if flush_initial_state:
            if not StateFlush.flush_all_state():
                logger.warning("Failed to flush initial state")
            
            StateFlush.flush_dns_cache()
        
        if not self.state_manager.capture_state():
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
      

        self.watchdog = FirewallWatchdog(
            group_name=self.backend.GROUP_NAME,
            on_tampering_detected=self._on_tampering_detected
        )
        
        if not self.watchdog.start():
            logger.warning("Watchdog failed to start (non-critical)")

        logger.info("LOCKDOWN ACTIVE WITH DNS FILTERING")
        logger.info(f"Allowed domains: {whitelist_domains}")
        logger.info(f"Interface Monitoring: {'Enabled' if self.interface_monitor else 'Disabled'}")
        return True
    
    def _on_dns_resolved(self, domain: str, ip: str):
        logger.info(f"Whitelisting {ip} for {domain}")
        rule_name_https = self.backend.add_allow_rule(ip, port=443, protocol="tcp")
        rule_name_http = self.backend.add_allow_rule(ip, port=80, protocol="tcp")
        
        self.watchdog.register_rule(rule_name_https)
        self.watchdog.register_rule(rule_name_http)

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
            if self.watchdog:
                self.watchdog.unregister_rule(rule_name)
            self.backend.delete_rule_by_name(rule_name)

    def _on_new_interface(self, interface_name: str):
        logger.warning(f"NEW NETWORK INTERFACE DETECTED: {interface_name}")
        logger.warning(f"Firewall rules automatically apply to this interface")
        logger.warning(f"If this is USB tethering, it will be blocked")
    
    def _on_tampering_detected(self, event_type: str, details: dict):
        logger.error("SECURITY ALERT: FIREWALL TAMPERING DETECTED!")
        logger.error(f"Type: {event_type}")
        logger.error(f"Details: {details}")
        logger.error("Administrator bypassing lockdown!")

        if event_type == "rule_deleted":
            self._reinstate_deleted_rule(details)
        
        elif event_type == "unauthorized_rule":
            self._remove_unauthorized_rule(details)
        
        elif event_type == "event_log_change":
            logger.error("Firewall modification detected via Event Log")
            logger.error("Manual investigation recommended")

    def _reinstate_deleted_rule(self, details: dict):
        rule_name = details.get('rule_name', '')
        
        logger.error(f"ATTEMPTING TO REINSTATE RULE: {rule_name}")
        
        if rule_name not in self.backend.rules:
            logger.error(f"Rule not found in registry (may be system rule)")
            return
    
        rule_info = self.backend.rules[rule_name]
        rule_type = rule_info.get('type')
        
        if rule_type == 'loopback':
            # Reinstate DNS rule
            logger.info(f"Re-adding loopback rule")
            try:
                self.backend._run_netsh(
                    f'advfirewall firewall add rule '
                    f'name="{rule_name}" '
                    f'dir=out '
                    f'action=allow '
                    f'remoteip=127.0.0.0/8 '
                    f'profile=any'
                )
                logger.info(f"   ✓ Loopback rule reinstated")
            except Exception as e:
                logger.error(f"   ✗ Failed to reinstate: {e}")
        
        elif rule_type == 'upstream_dns':
            # Reinstate DNS rule
            dns_ip = rule_info.get('ip')
            logger.info(f"Re-adding upstream DNS rule for {dns_ip}")
            
            try:
                self.backend._run_netsh(
                    f'advfirewall firewall add rule '
                    f'name="{rule_name}" '
                    f'dir=out '
                    f'action=allow '
                    f'protocol=UDP '
                    f'remoteip={dns_ip} '
                    f'remoteport=53 '
                    f'profile=any'
                )
                logger.info(f"DNS rule reinstated")
            except Exception as e:
                logger.error(f"Failed to reinstate: {e}")
        
        else:
            # Regular IP whitelist rule
            ip = rule_info.get('ip')
            port = rule_info.get('port')
            protocol = rule_info.get('protocol')
            
            if not all([ip, port, protocol]):
                logger.error(f"Incomplete rule info: {rule_info}")
                return
            
            logger.info(f"   Re-adding: {ip}:{port}/{protocol}")
            
            try:
                self.backend._run_netsh(
                    f'advfirewall firewall add rule '
                    f'name="{rule_name}" '
                    f'dir=out '
                    f'action=allow '
                    f'protocol={protocol} '
                    f'remoteip={ip} '
                    f'remoteport={port} '
                    f'profile=any '
                    f'interfacetype=any'
                )
                
                # Re-register with watchdog
                if self.watchdog:
                    self.watchdog.register_rule(rule_name)
                
                logger.info(f"Rule reinstated successfully")
                
            except Exception as e:
                logger.error(f"Failed to reinstate: {e}")

    def _remove_unauthorized_rule(self, details: dict):
        rule_name = details.get('rule_name', '')
        
        logger.error(f"REMOVING UNAUTHORIZED RULE: {rule_name}")
        
        try:
            subprocess.run(
                f'netsh advfirewall firewall delete rule name="{rule_name}"',
                shell=True,
                capture_output=True,
                check=True
            )
            
            logger.info(f"Unauthorized rule removed")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to remove rule: {e}")


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
        
        if self.watchdog:
            self.watchdog.stop()
        
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