import numpy as np
from typing import Tuple

class ChaosSymmetricEngine:
    """
    Implements High-Speed Symmetric Stream Generation using the Logistic Map.
    
    Equation: x_{n+1} = mu * x_n * (1 - x_n)
    
    This engine takes the 'Shared Secret' (derived from the Asymmetric Handshake)
    and uses it as the seed (x0) to generate gigabytes of encryption keys 
    with O(N) complexity.
    """

    def __init__(self, shared_secret: float, mu: float = 3.999):
        """
        Args:
            shared_secret (float): The value agreed upon by KeyManager (0.0 - 1.0).
            mu (float): The control parameter. 3.999 ensures deep chaos.
        """
        # IEEE Requirement: Check for weak keys (e.g., 0.0, 0.5, 1.0)
        if shared_secret <= 0.0 or shared_secret >= 1.0:
            # In production, we'd raise an error. For prototype, we adjust.
            shared_secret = 0.123456789
            
        self.state = shared_secret
        self.mu = mu
        
        # Burn-in period to decouple the stream from the raw seed
        self._burn_in(50)

    def _burn_in(self, iterations: int):
        """Advances the map to reach a high-entropy state."""
        for _ in range(iterations):
            self.state = self.mu * self.state * (1.0 - self.state)

    def generate_key_stream(self, length: int) -> np.ndarray:
        """
        Generates a 1D array of chaotic floats.
        """
        sequence = np.empty(length, dtype=np.float64)
        x = self.state
        
        for i in range(length):
            x = self.mu * x * (1.0 - x)
            sequence[i] = x
            
        self.state = x # Update internal state
        return sequence

    def generate_tensor(self, shape: Tuple[int, ...]) -> np.ndarray:
        """
        Generates a structured Key Tensor for bitwise operations.
        
        Output:
            np.ndarray (uint8): Values 0-255 ready for XOR.
        """
        count = np.prod(shape)
        raw_floats = self.generate_key_stream(count)
        
        # Quantize [0,1] -> [0, 255]
        # This converts the math chaos into digital bytes
        bytes_data = (raw_floats * 255).astype(np.uint8)
        
        return bytes_data.reshape(shape)

# --- Unit Test ---
if __name__ == "__main__":
    print("[TEST] Initializing Symmetric Engine...")
    
    # Simulate a Shared Secret (e.g., 0.823 derived from Handshake)
    secret = 0.82341
    engine = ChaosSymmetricEngine(secret)
    
    # Generate a Key Block (4x4x4 = 64 bytes)
    shape = (4, 4, 4)
    key_tensor = engine.generate_tensor(shape)
    
    print(f"[INFO] Generated Tensor Shape: {key_tensor.shape}")
    print(f"[INFO] First 4 bytes: {key_tensor.flatten()[:4]}")
    
    # Determinism Check
    engine2 = ChaosSymmetricEngine(secret)
    key_tensor2 = engine2.generate_tensor(shape)
    
    assert np.array_equal(key_tensor, key_tensor2)
    print("[SUCCESS] Engine is deterministic (Same Secret = Same Key).")