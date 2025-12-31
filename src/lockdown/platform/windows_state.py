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
        subprocess.run(f"netsh advfirewall set allprofiles firewallpolicy {original_policy}",
                       shell=True,
                       check=True,
                       capture_output=True
                       )
        logger.info("Restored the previous State of firewall.")

        firewall_state = state.get("firewall_state", {})
        if not firewall_state.get("enabled", True):
            subprocess.run(
                "netsh advfirewall set allprofiles state off",
                shell=True,
                capture_output=True
            )
        
        logger.info("Previous Firewall Satte recovery successful.")
        return True


    def _get_firewall_state(self) -> dict:
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
            return {"enabled": True} 
    
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
            subprocess.run(
                'netsh advfirewall firewall delete rule name=all dir=out',
                shell=True,
                capture_output=True,
                text=True
            )
            
            for prefix in ["CodeforcesLockdown_", "CodeforcesLockdown"]:
                try:
                    subprocess.run(
                        f'powershell -Command "Remove-NetFirewallRule -DisplayName \'{prefix}*\' -ErrorAction SilentlyContinue"',
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                except Exception:
                    pass
                    
        except Exception as e:
            logger.warning(f"Error during rule cleanup: {e}")
