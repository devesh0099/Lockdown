import subprocess
import logging

logger = logging.getLogger(__name__)

class WindowsState:
    
    def capture(self) -> dict:
        state = {
            "firewall_state": self._get_firewall_state(),
            "firewall_policy": self._get_firewall_policy(),
            "existing_rules_count": self._count_existing_rules()
        }
        
        logger.info(f"Captured Windows state (Policy: {state['firewall_policy']})")
        return state
    
    def _get_firewall_policy(self) -> str:
        try:
            result = subprocess.run(
                "netsh advfirewall show allprofiles",
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            
            output = result.stdout.lower()
            inbound_blocked = False
            outbound_blocked = False
            
            for line in output.splitlines():
                line = line.strip().lower()
                
                if 'firewall policy' in line or 'policy' in line:
                    if 'blockinbound' in line:
                        inbound_blocked = True
                    if 'allowinbound' in line:
                        inbound_blocked = False
                        
                    if 'blockoutbound' in line:
                        outbound_blocked = True
                    if 'allowoutbound' in line:
                        outbound_blocked = False
            
            inbound = "block" if inbound_blocked else "allow"
            outbound = "block" if outbound_blocked else "allow"
            
            policy = f"{inbound}inbound,{outbound}outbound"
            logger.debug(f"Detected firewall policy: {policy}")
            return policy
                    
        except Exception as e:
            logger.warning(f"Could not determine firewall policy: {e}")
            return "allowinbound,allowoutbound"

    def restore(self, state: dict) -> bool:
        try:
            logger.info("Restoring Windows firewall state...")
            
            self._delete_lockdown_rules()
            
            logger.info("Setting firewall policy to: allowinbound,allowoutbound")
            
            for attempt in range(3):
                result = subprocess.run(
                    "netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound",
                    shell=True,
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0:
                    logger.error(f"Attempt {attempt+1}: Command failed - {result.stderr}")
                    continue
                
                import time
                time.sleep(0.5)
                
                current_policy = self._get_firewall_policy()
                logger.info(f"Verification: Current policy is now: {current_policy}")
                
                if "allow" in current_policy and "outbound" in current_policy:
                    logger.info("Firewall policy successfully restored")
                    break
                else:
                    logger.warning(f"Attempt {attempt+1}: Policy not applied correctly, retrying...")
            else:
                logger.error("Failed to restore policy after 3 attempts")
                logger.error("MANUAL FIX REQUIRED:")
                logger.error("Open PowerShell as Admin and run:")
                logger.error("netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound")
                return False
            
            firewall_state = state.get("firewall_enabled", {})
            
            if isinstance(firewall_state, dict):
                firewall_enabled = firewall_state.get("enabled", True)
            else:
                firewall_enabled = firewall_state
            
            if not firewall_enabled:
                subprocess.run(
                    "netsh advfirewall set allprofiles state off",
                    shell=True,
                    capture_output=True
                )
                logger.info("Firewall disabled (as per original state)")
            
            logger.info("Windows state fully restored")
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore state: {e}")
            logger.error("MANUAL FIX REQUIRED:")
            logger.error("netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound")
            return False

    def _get_firewall_state(self) -> bool:
        try:
            result = subprocess.run(
                "netsh advfirewall show allprofiles state",
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            
            output = result.stdout.upper()
            enabled = "ON" in output or "STATE" in output
            
            return {"enabled": enabled}
            
        except Exception as e:
            logger.warning(f"Could not determine firewall state: {e}")
            return True 
    
    def _count_existing_rules(self) -> int:
        try:
            result = subprocess.run(
                "netsh advfirewall firewall show rule name=all",
                shell=True,
                capture_output=True,
                text=True
            )
            
            count = result.stdout.count("Rule Name:")
            return count
            
        except Exception:
            return 0
    
    def _delete_lockdown_rules(self):
        try:
            logger.info("Deleting lockdown firewall rules...")
            
            subprocess.run(
                'netsh advfirewall firewall delete rule name="CodeforcesLockdown_Loopback"',
                shell=True,
                capture_output=True
            )
            
            powershell_cmd = (
                'Get-NetFirewallRule | '
                'Where-Object {$_.DisplayName -like "CodeforcesLockdown*"} | '
                'Remove-NetFirewallRule'
            )
            
            subprocess.run(
                f'powershell -Command "{powershell_cmd}"',
                shell=True,
                capture_output=True,
                timeout=10
            )
            
            logger.info("Lockdown rules deleted")
                    
        except subprocess.TimeoutExpired:
            logger.warning("PowerShell deletion timed out")
        except Exception as e:
            logger.warning(f"Error during rule cleanup: {e}")

