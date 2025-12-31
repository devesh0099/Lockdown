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
    
    def restore(self, state: dict) -> bool:
        logger.info("Restoring Windows firewall state")

        self._delete_lockdown_rules()

        original_policy = state.get("firewall_policy","allowinbound,allowoutbound")
        logger.info(f"Restoring firewall policy to: {original_policy}")

        result = subprocess.run(f"netsh advfirewall set allprofiles firewallpolicy {original_policy}",
                       shell=True,
                       check=True,
                       capture_output=True
                       )
        if result.returncode != 0:
            logger.error(f"Failed to restore policy: {result.stderr}")
            return False
        logger.info("Restored firewall policy: allowinbound,allowoutbound")

        current_policy = self._get_firewall_policy()
        logger.info(f"Current policy after restore: {current_policy}")
            
        if "block" in current_policy.lower() and "outbound" in current_policy.lower():
            logger.warning("Outbound traffic is still blocked!")
            logger.warning("Manually run: netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound")
            return False

        firewall_state = state.get("firewall_state","enabled",True)
        if not firewall_state.get("enabled", True):
            subprocess.run(
                "netsh advfirewall set allprofiles state off",
                shell=True,
                capture_output=True
            )
        
        logger.info("Previous Firewall Satte recovery successful.")
        return True


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
    
    def _get_firewall_policy(self) -> str:
        try:
            result = subprocess.run(
                "netsh advfirewall show allprofiles",
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            
            output = result.stdout.upper()

            if "OUTBOUND" in output and "BLOCK" in output:
                return "blockinbound,blockoutbound"
            else:
                return "allowinbound,allowoutbound"
                
        except Exception as e:
            logger.warning(f"Could not determine firewall policy: {e}")
            return "allowinbound,allowoutbound"
    
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

