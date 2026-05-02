import sys
import os
import numpy as np

# Adjust path to allow imports from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from engine.chaos_symmetric import ChaosSymmetricEngine
from engine.tensor_ops import TensorOps

class EncryptionService:
    """
    High-level API for encrypting/decrypting data streams.
    
    Architecture:
    Input (Bytes) -> Padding -> Block Splitting -> Tensor Ops -> Output (Bytes)
    """

    def __init__(self, shared_secret: float, block_shape=(4, 4, 4)):
        self.block_shape = block_shape
        self.block_size = np.prod(block_shape) # 64 bytes
        self.secret = shared_secret
        
        # We need independent engines for encrypt/decrypt to maintain sync
        # In a real app, you might reset these per session.
        self.tx_engine = ChaosSymmetricEngine(shared_secret)
        self.rx_engine = ChaosSymmetricEngine(shared_secret)

    def _pad(self, data: bytes) -> bytes:
        """PKCS7 Padding to fit block size."""
        pad_len = self.block_size - (len(data) % self.block_size)
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data: bytes) -> bytes:
        """Removes PKCS7 padding."""
        if not data: return b""
        pad_len = data[-1]
        return data[:-pad_len]

    def _bytes_to_tensor(self, block: bytes) -> np.ndarray:
        return np.frombuffer(block, dtype=np.uint8).reshape(self.block_shape)

    def _tensor_to_bytes(self, tensor: np.ndarray) -> bytes:
        return tensor.tobytes()

    def encrypt_message(self, plaintext: str) -> bytes:
        """
        Full Encryption Pipeline.
        """
        # 1. Reset Engine for this message (Simulating 'Session Mode')
        # In continuous stream mode, we wouldn't reset.
        self.tx_engine = ChaosSymmetricEngine(self.secret)
        
        # 2. Prepare Data
        data_bytes = plaintext.encode('utf-8')
        padded_data = self._pad(data_bytes)
        
        encrypted_blocks = []
        
        # 3. Process Chunk by Chunk
        for i in range(0, len(padded_data), self.block_size):
            chunk = padded_data[i : i + self.block_size]
            data_tensor = self._bytes_to_tensor(chunk)
            
            # Generate Unique Key Tensors for this specific block
            # Note: We generate 2 keys: one for XOR, one for Rotation/Permutation
            key_xor = self.tx_engine.generate_tensor(self.block_shape)
            key_rot = self.tx_engine.generate_tensor(self.block_shape)
            
            # Apply The "Blender" Layers
            # Layer 1: XOR
            t1 = TensorOps.apply_xor(data_tensor, key_xor)
            # Layer 2: Rotation (Use first byte of key_rot as shift amount)
            t2 = TensorOps.apply_rotation(t1, key_rot)
            # Layer 3: Permutation (Use sum of key_rot as seed)
            seed = int(np.sum(key_rot))
            t3 = TensorOps.apply_permutation(t2, seed)
            
            encrypted_blocks.append(self._tensor_to_bytes(t3))
            
        return b"".join(encrypted_blocks)

    def decrypt_message(self, ciphertext: bytes) -> str:
        """
        Full Decryption Pipeline.
        """
        self.rx_engine = ChaosSymmetricEngine(self.secret)
        
        decrypted_blocks = []
        
        for i in range(0, len(ciphertext), self.block_size):
            chunk = ciphertext[i : i + self.block_size]
            data_tensor = self._bytes_to_tensor(chunk)
            
            # Re-generate exact same keys
            key_xor = self.rx_engine.generate_tensor(self.block_shape)
            key_rot = self.rx_engine.generate_tensor(self.block_shape)
            
            # Reverse The Layers (Order Matters!)
            # Reverse Layer 3: Permutation
            seed = int(np.sum(key_rot))
            t1 = TensorOps.reverse_permutation(data_tensor, seed)
            # Reverse Layer 2: Rotation
            t2 = TensorOps.reverse_rotation(t1, key_rot)
            # Reverse Layer 1: XOR
            t3 = TensorOps.apply_xor(t2, key_xor)
            
            decrypted_blocks.append(self._tensor_to_bytes(t3))
            
        full_padded = b"".join(decrypted_blocks)
        return self._unpad(full_padded).decode('utf-8')

# --- Unit Test ---
if __name__ == "__main__":
    print("[TEST] Initializing Encryption Service...")
    
    # Shared Secret from Handshake
    secret = 0.555123
    service = EncryptionService(secret)
    
    msg = "This is a Top Secret IEEE Paper Submission!"
    print(f"[INPUT] Original: '{msg}'")
    
    # Encrypt
    cipher = service.encrypt_message(msg)
    print(f"[OUTPUT] Cipher (Hex): {cipher.hex()[:64]}...")
    
    # Decrypt
    # Verify we can decrypt with a fresh service instance using same secret
    receiver = EncryptionService(secret)
    plain = receiver.decrypt_message(cipher)
    print(f"[OUTPUT] Decrypted: '{plain}'")
    
    assert msg == plain
    print("[SUCCESS] Service functions end-to-end.")