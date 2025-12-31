import subprocess
import logging

logger = logging.getLogger(__name__)


class WindowsDNS:
    def set_dns_to_localhost(self) -> bool:
        try:
            interfaces = self._get_active_interfaces()
            
            if not interfaces:
                logger.error("No active network interfaces found")
                return False
            
            for interface in interfaces:
                try:
                    subprocess.run(
                        f'netsh interface ipv4 set dnsservers name="{interface}" static 127.0.0.1 primary',
                        shell=True,
                        check=True,
                        capture_output=True,
                        text=True
                    )
                    logger.info(f"Set DNS to 127.0.0.1 for interface: {interface}")
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Failed to set DNS for {interface}: {e}")
            
            subprocess.run("ipconfig /flushdns", shell=True, capture_output=True)
            logger.info("DNS cache flushed")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to configure DNS: {e}")
            return False
    
    def restore_dns_to_dhcp(self) -> bool:
        try:
            interfaces = self._get_active_interfaces()
            
            for interface in interfaces:
                try:
                    subprocess.run(
                        f'netsh interface ipv4 set dnsservers name="{interface}" source=dhcp',
                        shell=True,
                        check=True,
                        capture_output=True
                    )
                    logger.info(f"Restored DHCP DNS for: {interface}")
                except subprocess.CalledProcessError:
                    logger.warning(f"Could not restore DNS for {interface}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore DNS: {e}")
            return False
    
    def _get_active_interfaces(self) -> list:
        try:
            result = subprocess.run(
                'netsh interface ipv4 show interfaces',
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
        
            interfaces = []
            for line in result.stdout.splitlines():
                if "connected" in line.lower() and "dedicated" in line.lower():
                    parts = line.split()
                    if len(parts) >= 4:
                        interface_name = ' '.join(parts[3:])
                        interfaces.append(interface_name)
            
            return interfaces
            
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")
            return []
