import sys
import os

# Adjust path to allow imports from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from engine.chaos_asymmetric import ChebyshevKeyExchange
from identity.hardware_fingerprint import HardwareFingerprint

class KeyManager:
    """
    Manages the lifecycle of Chaotic Public/Private Keys.
    
    Protocol Constant:
    GLOBAL_SEED_X (float): A publicly known parameter for the Chebyshev map.
    In a real system, this could be rotated daily or derived from the date.
    For this prototype, it is fixed.
    """
    
    # The common 'x' in T_n(x). Must be in (-1, 1).
    PROTOCOL_SEED_X = 0.192837465 

    def __init__(self, hardware_id: str):
        self.device_id = hardware_id
        self.engine = ChebyshevKeyExchange()
        
        self._private_key = None
        self.public_key = None
        
        # Initialize identity immediately
        self._generate_identity()

    def _generate_identity(self):
        """Creates a fresh KeyPair for this session."""
        # The private key is a large integer
        # The public key is a float: T_priv(x)
        self._private_key, self.public_key = self.engine.generate_keypair(self.PROTOCOL_SEED_X)

    def get_public_key(self) -> float:
        """Returns the Public Key to be shared with peers."""
        return self.public_key

    def compute_shared_secret(self, peer_public_key: float) -> float:
        """
        Derives the Session Key using the Peer's Public Key.
        
        Input: Peer's Public Key (float)
        Output: Shared Secret (float [0, 1])
        """
        if peer_public_key is None:
            raise ValueError("Peer Public Key cannot be None")
            
        return self.engine.derive_shared_secret(peer_public_key, self._private_key)

# --- Unit Test ---
if __name__ == "__main__":
    print("[TEST] Initializing Key Manager...")
    
    # Simulate Router A
    hw_a = HardwareFingerprint()
    km_a = KeyManager(hw_a.get_device_id())
    print(f"[NODE A] ID: {km_a.device_id}")
    print(f"[NODE A] Public Key: {km_a.get_public_key():.6f}")
    
    # Simulate Router B
    hw_b = HardwareFingerprint() # In real run, this would be a diff device
    km_b = KeyManager("DEVICE_B_MOCK")
    print(f"[NODE B] ID: {km_b.device_id}")
    print(f"[NODE B] Public Key: {km_b.get_public_key():.6f}")
    
    # Simulate Handshake (Exchange Keys)
    secret_at_a = km_a.compute_shared_secret(km_b.get_public_key())
    secret_at_b = km_b.compute_shared_secret(km_a.get_public_key())
    
    print(f"\n[RESULT] Shared Secret A: {secret_at_a:.10f}")
    print(f"[RESULT] Shared Secret B: {secret_at_b:.10f}")
    
    # Verification
    import math
    assert math.isclose(secret_at_a, secret_at_b, rel_tol=1e-9)
    print("[SUCCESS] Key Managers successfully derived the same secret.")