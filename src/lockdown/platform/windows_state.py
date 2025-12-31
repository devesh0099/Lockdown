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
        
        logger.info(f"✓ Captured Windows state (Policy: {state['firewall_policy']})")
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


    