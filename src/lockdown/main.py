import logging
import sys
import signal
import atexit
from core.firewall_manager import FirewallManager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

firewall = None

def cleanup():
    if firewall and firewall.backend.is_active:
        logger.info("\nCleaning up...")
        firewall.disable_lockdown()

def signal_handler(signum, frame):
    logger.info("\nInterrupt received")
    cleanup()
    sys.exit(0)

def test_dns_lockdown():
    global firewall
    
    print("CODEFORCES LOCKDOWN - DNS INTERCEPTION TEST")
    
    if not is_admin():
        logger.error("Run as Administrator")
        return False
    
    firewall = FirewallManager()
    
    print("\nEnabling lockdown with DNS filtering...")
    if not firewall.enable_lockdown():
        return False
    
    print("\nLockdown + DNS interception active!")
    print("\nTEST 1: Try opening codeforces.com in your browser")
    print("Expected: Should work (DNS resolves, IP whitelisted)")
    
    input("\n⏸Press Enter after testing Codeforces...")
    
    print("\nTEST 2: Try opening google.com")
    print("Expected: Should fail (DNS blocked)")
    
    input("\n⏸Press Enter after testing Google...")
    
    print("\nCurrently whitelisted IPs:")
    for ip in firewall.get_whitelisted_ips():
        print(f"   - {ip}")
    
    input("\nPress Enter to restore system...")
    
    cleanup()
    print("\nTEST COMPLETE - System restored\n")
    return True

def test_lockdown():
    global firewall
    
    print("LOCKDOWN - TEST MODE")
    
    if not is_admin():
        return False
    
    firewall = FirewallManager()
    
    print("\nStep 1: Enabling lockdown...")
    if not firewall.enable_lockdown():
        logger.error("Failed to enable lockdown")
        return False
    
    print("\nLockdown enabled!")
    print("\nTEST: Try opening any website in your browser")
    print("Expected: Connection should timeout/fail")
    
    input("\n ⏸Press Enter after testing (websites should be blocked)...")
    
    print("\nStep 2: Whitelisting 8.8.8.8:443 (Google DNS)...")
    firewall.allow_ip("8.8.8.8", port=443, protocol="tcp")
    
    print("\nIP whitelisted!")
    print("\nTEST: Try this command in PowerShell:")
    print("Test-NetConnection -ComputerName 8.8.8.8 -Port 443")
    print("Expected: Connection should succeed")
    
    input("\n⏸Press Enter to disable lockdown and restore system...")
    
    print("\nStep 3: Restoring system...")
    cleanup()
    
    print("TEST COMPLETE")
    print("\nYour system has been restored to its original state")
    print("   You can verify by opening any website\n")
    
    return True


def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def main():
    atexit.register(cleanup)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        test_dns_lockdown()
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        cleanup()
        sys.exit(1)


if __name__ == "__main__":
    main()