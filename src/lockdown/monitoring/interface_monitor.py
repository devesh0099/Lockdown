import subprocess
import threading
import time
import logging
from typing import Set, Callable, Optional

logger = logging.getLogger(__name__)

class InterfaceMonitor:
    def __init__(self, on_new_interface: Optional[Callable] = None):
        self.on_new_interface = on_new_interface
        self.known_interfaces: Set[str] = set()
        self.running = False
        self.thread = None

    def start(self) -> bool:
        try:
            self.known_interfaces = self._get_active_interfaces()
            self.running = True
            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()

            return True
        
        except Exception as e:
            return False
    
    def stop(self):
        logger.info("Stopping interface monitor")
        self.running = False

        if self.thread:
            self.thread.join(timeout=2)

        logger.info("Interface monitor stopped")

    def _monitor_loop(self):
        while self.running:
            try:
                current_interfaces = self._get_active_interfaces()
                
                new_interfaces = current_interfaces - self.known_interfaces
                
                if new_interfaces:
                    for interface in new_interfaces:
                        logger.warning(f"NEW INTERFACE DETECTED: {interface}")
                        
                        if self.on_new_interface:
                            self.on_new_interface(interface)
                    
                    self.known_interfaces = current_interfaces
                
                removed_interfaces = self.known_interfaces - current_interfaces
                if removed_interfaces:
                    logger.info(f"Interface removed: {removed_interfaces}")
                    self.known_interfaces = current_interfaces
                
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Error in interface monitor: {e}")
                time.sleep(5)

    def _get_active_interfaces(self) -> Set[str]:
        try:
            result = subprocess.run(
                'powershell -Command "Get-NetAdapter | Where-Object {$_.Status -eq \'Up\'} | Select-Object -ExpandProperty Name"',
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip():
                interfaces = {line.strip() for line in result.stdout.splitlines() if line.strip()}
                return interfaces
            
            return set()
            
        except subprocess.TimeoutExpired:
            logger.warning("Interface detection timed out")
            return set()
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
            return set()

