import subprocess
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class WindowsFirewall:
    def __init__(self):

        self.GROUP_NAME = "CodeforcesLockdown"

        self.is_active = False
        self.rules = {}

    def initialize(self) -> bool:
        try:
            logger.info("Initializing Windows Firewall")

            #Enablling Firewall
            self._run_netsh("advfirewall set allprofiles state on")

            # Set policy to BLOCK ALL
            self._run_netsh(
                "advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound"
            )
            logger.info("Block all connection rule added")

            # Allowed loopback
            rule_name = f"{self.GROUP_NAME}_Loopback"
            self._run_netsh(
                f'advfirewall firewall add rule'
                f'name="{rule_name}" '
                f'dir=out '
                f'action=allow '
                f'remoteip=127.0.0.1 '
                f'profile=any'
            )
            self.rules[rule_name] = {"type": "loopback", "ip": "127.0.0.1"}
            logger.info("Allowed loopback")

            self.is_active = True
            logger.info("Firewall Activated")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to initialize firewall: {e}")
            logger.error(f"Command output: {e.output if hasattr(e, 'output') else 'N/A'}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during initialization: {e}")
            return False
    
    def add_allow_rule(self, ip: str, port: int, protocol: str = "tcp") -> Optional[str]:
        try:
            rule_name = f"{self.GROUP_NAME}_{ip.replace('.','_')}_{port}_{protocol.upper()}"

            self._run_netsh(
                f'advfirewall firewall add rule'
                f'name="{rule_name}" '
                f'dir=out '
                f'action=allow '
                f'protocol={protocol.upper()} '
                f'remoteip={ip} '
                f'remoteport={port} '
                f'profile=any'
            )

            self.rules[rule_name] = {
                "ip": ip,
                "port": port,
                "protocol": protocol.upper()
            }

            logger.info(f"Added {ip}:{port}/{protocol.upper()} to allowlist")
            return rule_name

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to add rule for {ip}:{port} - {e}")
            return None
        

    def delete_rule_by_name(self, rule_name: str) -> bool:
        try:
            self._run_netsh(f'advfirewall firewall delete rule name="{rule_name}"')

            if rule_name in self.rules:
                rule_info = self.rules[rule_name]
                logger.info(f"Deleted rule for {rule_info.get('ip', 'unknown')}")
                del self.rules[rule_name]

            return True
        
        except subprocess.CalledProcessError:
            logger.warning(f"Rule not found or already deleted: {rule_name}")
            return False
        
    def delete_rule_by_ip(self, ip: str, port: int, protocol: str = "tcp") -> bool:
        rule_name = f"{self.GROUP_NAME}_{ip.replace('.', '_')}_{port}_{protocol.upper()}"
        return self.delete_rule_by_name(rule_name)
    
    def shutdown(self) -> bool:

        for rule_name in list(self.rules.keys()):
            self.delete_rule_by_name(rule_name)

        self.rules.clear()
        self.is_active = False
        logger.info("Lockdown is removed")
        return True
    

    def get_active_rules(self) -> list[dict]:
        return [
            {"name": name, **details}
            for name, details in self.rules.items()
            if details.get("type") != "loopback"
        ]
    
    def list_all_rules(self) -> str:
        return self._run_netsh("advfirewall firewall show rule name=all")
        

    def _run_netsh(self, command: str) -> str:
        full_cmd = f"netsh {command}"

        logger.debug(f"Executing: {full_cmd}")

        result = subprocess.run(
            full_cmd,
            shell=True,
            check=True,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        
        return result.stdout.strip()