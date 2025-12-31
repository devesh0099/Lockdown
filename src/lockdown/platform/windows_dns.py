import subprocess
import logging

logger = logging.getLogger(__name__)


class WindowsDNS:
    def set_dns_to_localhost(self) -> bool:
        try:
            interfaces = self._get_active_interfaces()
            
            if not interfaces:
                logger.error("No active network interfaces found")
                self._debug_show_interfaces()
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
                'powershell -Command "Get-NetAdapter | Where-Object {$_.Status -eq \'Up\'} | Select-Object -ExpandProperty Name"',
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
        
            if result.returncode == 0 and result.stdout.strip():
                interfaces = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                logger.debug(f"Found interfaces via PowerShell: {interfaces}")
                return interfaces
            
            result = subprocess.run(
                'netsh interface ipv4 show interfaces',
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            
            interfaces = []
            for line in result.stdout.splitlines():
                line = line.strip()
                
                if not line or 'Idx' in line or '---' in line:
                    continue
                
                if 'connected' in line.lower():
                    parts = line.split()
                    if len(parts) >= 5:
                        status_idx = -1
                        for i, part in enumerate(parts):
                            if 'connected' in part.lower():
                                status_idx = i
                                break
                        
                        if status_idx >= 0 and status_idx + 1 < len(parts):
                            interface_name = ' '.join(parts[status_idx + 1:])
                            interfaces.append(interface_name)
            
            logger.debug(f"Found interfaces via netsh: {interfaces}")
            return interfaces
            
        except subprocess.TimeoutExpired:
            logger.error("PowerShell command timed out")
            return []
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")
            return []
    
    def _debug_show_interfaces(self):
        try:
            result = subprocess.run(
                'netsh interface ipv4 show interfaces',
                shell=True,
                capture_output=True,
                text=True
            )
            logger.error(result.stdout)
        except Exception:
            pass