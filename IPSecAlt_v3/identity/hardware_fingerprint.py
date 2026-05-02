import uuid
import platform
import hashlib
import json
import os

class HardwareFingerprint:
    """
    Simulates a Physical Unclonable Function (PUF) for Device Identity.
    
    Research Context:
    Binds the software cryptographic layer to the specific hardware node.
    In a real FPGA implementation, this would query silicon gate variations.
    Here, it aggregates system serials to create a unique 'Node ID'.
    """

    def __init__(self):
        self._fingerprint = None
        self._device_id = None
        self._derive_fingerprint()

    def _get_mac_address(self) -> str:
        """Retrieves the physical MAC address."""
        try:
            mac_num = uuid.getnode()
            return ':'.join(('%012X' % mac_num)[i:i+2] for i in range(0, 12, 2))
        except:
            return "00:00:00:00:00:00"

    def _derive_fingerprint(self):
        """
        Aggregates immutable hardware signals into a SHA-256 signature.
        """
        # 1. Gather Hardware Info (Entropy Source)
        info = {
            "node": platform.node(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "mac": self._get_mac_address(),
            "os": os.name
        }
        
        # 2. Serialize and Hash
        # sort_keys=True ensures deterministic output for the same device
        raw_data = json.dumps(info, sort_keys=True)
        self._fingerprint = hashlib.sha256(raw_data.encode()).hexdigest()
        
        # 3. Create Short ID (First 16 chars) for easy logging
        self._device_id = self._fingerprint[:16]

    def get_device_id(self) -> str:
        """Returns the short 16-character Node ID."""
        return self._device_id

    def get_full_fingerprint(self) -> str:
        """Returns the complete hardware hash."""
        return self._fingerprint

# --- Unit Test ---
if __name__ == "__main__":
    print("[TEST] Scanning Hardware Identity...")
    hw = HardwareFingerprint()
    print(f"[INFO] Device ID: {hw.get_device_id()}")
    print(f"[INFO] Fingerprint: {hw.get_full_fingerprint()}")
    
    # Consistency Check
    hw2 = HardwareFingerprint()
    assert hw.get_device_id() == hw2.get_device_id()
    print("[SUCCESS] Hardware Identity is deterministic.")