import subprocess
import logging
import time

logger = logging.getLogger(__name__)


class StateFlush:
    @staticmethod
    def flush_all_state() -> bool:
        logger.info("FLUSHING NETWORK STATE")
        
        success = True
        
        if not StateFlush.flush_dns_cache():
            success = False
        
        if not StateFlush.kill_existing_connections():
            success = False
        
        if not StateFlush.flush_arp_cache():
            success = False
        
        if success:
            logger.info("NETWORK STATE FLUSHED")
        else:
            logger.warning("PARTIAL FLUSH (some operations failed)")
        return success
    
    @staticmethod
    def flush_dns_cache() -> bool:
        try:
            logger.info("Flushing DNS cache")
            
            result = subprocess.run(
                "ipconfig /flushdns",
                shell=True,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logger.info("✓ DNS cache flushed")
                return True
            else:
                logger.warning(f"Failed to flush DNS cache: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error flushing DNS cache: {e}")
            return False
    
    @staticmethod
    def kill_existing_connections() -> bool:
        try:
            logger.info("Terminating existing TCP connections...")
            
            result = subprocess.run(
                'netstat -ano | findstr ESTABLISHED',
                shell=True,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0 and not result.stdout.strip():
                logger.info("No existing connections to terminate")
                return True
            
            connections = []
            
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 5:
                    continue
                
                # Format: TCP  LocalAddr:Port  RemoteAddr:Port  ESTABLISHED  PID
                protocol = parts[0]
                local_addr = parts[1]
                remote_addr = parts[2]
                pid = parts[4]
                
                # Skip localhost connections
                if '127.0.0.1' in remote_addr or '[::1]' in remote_addr:
                    continue
                
                # Skip system processes
                if pid in ['0', '4']:
                    continue
                
                connections.append({
                    'local': local_addr,
                    'remote': remote_addr,
                    'pid': pid
                })
            
            if not connections:
                logger.info("No user connections to terminate")
                return True
            
            logger.info(f"Found {len(connections)} established connection(s)")
            
            terminated = 0
            
            for conn in connections:
                try:
                    local_parts = conn['local'].rsplit(':', 1)
                    remote_parts = conn['remote'].rsplit(':', 1)
                    
                    if len(local_parts) != 2 or len(remote_parts) != 2:
                        continue
                    
                    local_ip = local_parts[0]
                    local_port = local_parts[1]
                    remote_ip = remote_parts[0]
                    remote_port = remote_parts[1]
                    
                    if '[' in local_ip or '[' in remote_ip:
                        continue
                    
                    logger.info(f"  Closing: {local_ip}:{local_port} → {remote_ip}:{remote_port}")
                    
                    ps_command = (
                        f'Get-NetTCPConnection -LocalAddress {local_ip} -LocalPort {local_port} '
                        f'-RemoteAddress {remote_ip} -RemotePort {remote_port} -ErrorAction SilentlyContinue | '
                        f'ForEach-Object {{ $_.Close() }}'
                    )
                    
                    result = subprocess.run(
                        f'powershell -Command "{ps_command}"',
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=2
                    )
                    
                    if result.returncode != 0:
                        temp_rule_name = f"TEMP_BLOCK_{remote_ip}_{remote_port}"
                        
                        subprocess.run(
                            f'netsh advfirewall firewall add rule '
                            f'name="{temp_rule_name}" '
                            f'dir=out '
                            f'action=block '
                            f'remoteip={remote_ip} '
                            f'remoteport={remote_port} '
                            f'protocol=TCP',
                            shell=True,
                            capture_output=True,
                            timeout=2
                        )
                        
                        time.sleep(0.1)
                        
                        subprocess.run(
                            f'netsh advfirewall firewall delete rule name="{temp_rule_name}"',
                            shell=True,
                            capture_output=True
                        )
                    
                    terminated += 1
                    
                except subprocess.TimeoutExpired:
                    logger.warning(f"  Timeout closing connection")
                except Exception as e:
                    logger.warning(f"  Error closing connection: {e}")
            
            logger.info(f"Attempted to close {terminated} connection(s)")
            logger.info("Note: Connections will naturally terminate when firewall blocks them")
            
            return True
            
        except Exception as e:
            logger.error(f"Error terminating connections: {e}")
            return False
    
    @staticmethod
    def flush_arp_cache() -> bool:
        try:
            logger.info("Flushing ARP cache")
            
            result = subprocess.run(
                "netsh interface ip delete arpcache",
                shell=True,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0 or "Ok" in result.stdout:
                logger.info("✓ ARP cache flushed")
                return True
            else:
                logger.warning(f"Failed to flush ARP cache: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error flushing ARP cache: {e}")
            return False
    
    @staticmethod
    def _is_critical_process(process_name: str) -> bool:
        critical_processes = [
            'system',
            'smss.exe',
            'csrss.exe',
            'wininit.exe',
            'services.exe',
            'lsass.exe',
            'svchost.exe',
            'winlogon.exe',
            'explorer.exe',
            'dwm.exe',
            'taskmgr.exe',
            'conhost.exe',
            'python.exe',
            'pythonw.exe',
            'cmd.exe',
            'powershell.exe',
            'pwsh.exe'
        ]
        
        return process_name.lower() in critical_processes
    
    @staticmethod
    def close_browser_connections() -> bool:
        try:
            logger.info("Closing browser connections...")
            
            browsers = [
                'chrome.exe',
                'msedge.exe',
                'firefox.exe',
                'opera.exe',
                'brave.exe',
                'iexplore.exe'
            ]
            
            closed = 0
            
            for browser in browsers:
                result = subprocess.run(
                    f'taskkill /IM {browser} /F',
                    shell=True,
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    logger.info(f"Closed {browser}")
                    closed += 1
            
            if closed > 0:
                logger.info(f"Closed {closed} browser(s)")
                time.sleep(1)
            else:
                logger.info("No browsers running")
            
            return True
            
        except Exception as e:
            logger.error(f"Error closing browsers: {e}")
            return False
    
    @staticmethod
    def get_active_connections() -> list:
        try:
            result = subprocess.run(
                'netstat -ano | findstr ESTABLISHED',
                shell=True,
                capture_output=True,
                text=True
            )
            
            connections = []
            
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5:
                    connections.append({
                        'protocol': parts[0],
                        'local': parts[1],
                        'remote': parts[2],
                        'state': parts[3],
                        'pid': parts[4]
                    })
            
            return connections
            
        except Exception as e:
            logger.error(f"Error getting connections: {e}")
            return []
