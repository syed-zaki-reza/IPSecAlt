import numpy as np

class TensorOps:
    """
    The 'Digital Blender'. Performs non-linear bitwise operations 
    on data tensors using chaotic keys.
    """

    @staticmethod
    def apply_xor(data_tensor: np.ndarray, key_tensor: np.ndarray) -> np.ndarray:
        """Layer 1: Standard Bitwise XOR (Confusion)."""
        return np.bitwise_xor(data_tensor, key_tensor)

    @staticmethod
    def apply_rotation(data_tensor: np.ndarray, rotation_key: np.ndarray) -> np.ndarray:
        """
        Layer 2: Chaotic Bit-Rotation.
        Each byte is rotated by 0-7 bits determined by the rotation_key.
        """
        # Ensure rotation key is in range [0, 7]
        shifts = rotation_key % 8
        
        # We use bitwise ops to simulate circular shift (rotation)
        # Formula: (x << n) | (x >> (8 - n))
        left_part = (data_tensor << shifts).astype(np.uint8)
        right_part = (data_tensor >> (8 - shifts)).astype(np.uint8)
        
        return left_part | right_part

    @staticmethod
    def apply_permutation(data_tensor: np.ndarray, seed: int) -> np.ndarray:
        """
        Layer 3: Non-linear Shuffling (Diffusion).
        Rearranges the indices of the tensor based on a deterministic seed.
        """
        shape = data_tensor.shape
        flat = data_tensor.flatten()
        
        # Create a deterministic shuffle index
        rng = np.random.default_rng(seed)
        indices = np.arange(len(flat))
        rng.shuffle(indices)
        
        # Apply the shuffle and reshape back
        shuffled = flat[indices]
        return shuffled.reshape(shape)

    @staticmethod
    def reverse_rotation(data_tensor: np.ndarray, rotation_key: np.ndarray) -> np.ndarray:
        """Inverse of apply_rotation (for decryption)."""
        shifts = rotation_key % 8
        # To reverse a left rotate by N, we right rotate by N
        right_part = (data_tensor >> shifts).astype(np.uint8)
        left_part = (data_tensor << (8 - shifts)).astype(np.uint8)
        
        return right_part | left_part

    @staticmethod
    def reverse_permutation(data_tensor: np.ndarray, seed: int) -> np.ndarray:
        """Inverse of apply_permutation (for decryption)."""
        shape = data_tensor.shape
        flat = data_tensor.flatten()
        
        rng = np.random.default_rng(seed)
        indices = np.arange(len(flat))
        rng.shuffle(indices)
        
        # To undo a shuffle, we place elements back into their original slots
        original = np.empty_like(flat)
        original[indices] = flat
        
        return original.reshape(shape)

# --- Unit Test ---
if __name__ == "__main__":
    print("[TEST] Testing Tensor Ops...")
    
    # Mock data: A 2x2 'image' block
    original_data = np.array([[65, 66], [67, 68]], dtype=np.uint8) # "ABCD"
    key = np.array([[10, 20], [30, 40]], dtype=np.uint8)
    
    print(f"Original: \n{original_data}")
    
    # Encrypt
    c1 = TensorOps.apply_xor(original_data, key)
    c2 = TensorOps.apply_rotation(c1, key)
    c3 = TensorOps.apply_permutation(c2, seed=123)
    
    print(f"Encrypted (Ciphertext): \n{c3}")
    
    # Decrypt
    d1 = TensorOps.reverse_permutation(c3, seed=123)
    d2 = TensorOps.reverse_rotation(d1, key)
    d3 = TensorOps.apply_xor(d2, key)
    
    print(f"Decrypted: \n{d3}")
    
    assert np.array_equal(original_data, d3)
    print("[SUCCESS] Data integrity maintained through all 3 layers.")