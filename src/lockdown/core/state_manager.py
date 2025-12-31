import json
import logging
from pathlib import Path
from typing import Optional
from datetime import datetime
from platform.windows_state import WindowsState

logger = logging.getLogger(__name__)

class StateManager:
    SNAPSHOT_DIR = Path.home() / ".lockdown"
    SNAPSHOT_FILE = SNAPSHOT_DIR / "state.json"

    def __init__(self):
        self.backend = WindowsState()
        self.snapshot = None
        
        self.SNAPSHOT_DIR.mkdir(exist_ok=True)


    def capture_state(self) -> bool:
        try:
            state = self.backend.capture()
            
            if not state:
                logger.error("Backend returned empty state")
                return False
            
            state["timestamp"] = datetime.now().isoformat()
            state["platform"] = "Windows"
            
            with open(self.SNAPSHOT_FILE, 'w') as f:
                json.dump(state, f, indent=2)
            
            self.snapshot = state
            logger.info(f"State saved to {self.SNAPSHOT_FILE}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to capture state: {e}", exc_info=True)
            return False
        
    def restore_state(self) -> bool:
        try:
            if self.snapshot is None:
                if not self.SNAPSHOT_FILE.exists():
                    logger.warning("No snapshot found - skipping restore")
                    return True
                
                with open(self.SNAPSHOT_FILE, 'r') as f:
                    self.snapshot = json.load(f)
            
            success = self.backend.restore(self.snapshot)
            
            if success:
                self.SNAPSHOT_FILE.unlink(missing_ok=True)
                logger.info("Snapshot file removed")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to restore state: {e}", exc_info=True)
            return False