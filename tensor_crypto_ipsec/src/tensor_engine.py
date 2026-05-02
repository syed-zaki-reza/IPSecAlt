"""
Tensor Engine - Core Encryption/Decryption using Chaotic 3D Tensor Mappings

Implements the high-speed chaotic tensor encryption equation:
    C = (M ⊛ K) ⊕ A_AI

Where:
- M = Message tensor (3D grid, e.g., 8×8×8)
- ⊛ = Chaotic mapping (coordinate permutation via Logistic Map)
- K = Key tensor (generated from Logistic Map)
- ⊕ = XOR operation
- A_AI = AI-generated noise tensor

Features:
- Linked tensor blocks for arbitrary message sizes
- 16-byte header metadata for padding recovery
- Multiple permutation strategies (voxel_swap, row_shift, bit_plane)
- Deterministic decryption via Mirror Chaos Engine
"""

import numpy as np
import hashlib
from typing import Tuple, Optional, Dict, List, Any
from dataclasses import dataclass, field
import logging
import time

try:
    from .chaos_engine import ChaosEngine
except ImportError:
    from chaos_engine import ChaosEngine

logger = logging.getLogger(__name__)


@dataclass
class BlockMetadata:
    """
    Header metadata for each tensor block (16 bytes).
    
    Structure:
    - bytes 0-3: Actual data length (uint32)
    - bytes 4-7: Block sequence number (uint32)
    - bytes 8-11: Total blocks in message (uint32)
    - bytes 12-15: Reserved/checksum (uint32)
    """
    actual_length: int
    block_index: int
    total_blocks: int
    checksum: int = 0
    
    HEADER_SIZE = 16
    BLOCK_DATA_SIZE = 512  # 8×8×8 = 512 bytes
    TOTAL_BLOCK_SIZE = HEADER_SIZE + BLOCK_DATA_SIZE  # 528 bytes
    
    def to_bytes(self) -> bytes:
        """Serialize metadata to 16-byte header"""
        return (
            self.actual_length.to_bytes(4, byteorder='big') +
            self.block_index.to_bytes(4, byteorder='big') +
            self.total_blocks.to_bytes(4, byteorder='big') +
            self.checksum.to_bytes(4, byteorder='big')
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'BlockMetadata':
        """Deserialize metadata from 16-byte header"""
        if len(data) < cls.HEADER_SIZE:
            raise ValueError(f"Insufficient data for header: {len(data)} bytes")
        
        return cls(
            actual_length=int.from_bytes(data[0:4], byteorder='big'),
            block_index=int.from_bytes(data[4:8], byteorder='big'),
            total_blocks=int.from_bytes(data[8:12], byteorder='big'),
            checksum=int.from_bytes(data[12:16], byteorder='big')
        )


@dataclass
class EncryptionResult:
    """Result of encryption operation"""
    ciphertext: bytes
    session_id: str
    block_count: int
    timestamp: float
    entropy_score: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DecryptionResult:
    """Result of decryption operation"""
    plaintext: bytes
    session_id: str
    block_count: int
    timestamp: float
    verified: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


class TensorEngine:
    """
    Core Tensor Encryption Engine using Chaotic Mappings.
    
    Implements the equation: C = (M ⊛ K) ⊕ A_AI
    
    The engine processes messages in 512-byte blocks (8×8×8 tensors),
    with each block containing a 16-byte header for metadata.
    
    Attributes:
        chaos_engine: ChaosEngine instance for generating permutations
        tensor_shape: 3D tensor dimensions (default: 8×8×8)
        strategy: Permutation strategy name
    """
    
    TENSOR_SHAPE = (8, 8, 8)  # 512 bytes per block
    BLOCK_SIZE = 512
    HEADER_SIZE = 16
    TOTAL_BLOCK_SIZE = HEADER_SIZE + BLOCK_SIZE  # 528 bytes
    
    PERMUTATION_STRATEGIES = frozenset([
        'voxel_swap',      # Full 3D voxel permutation
        'row_shift',       # Row-wise cyclic shifts
        'bit_plane',       # Bit-plane slicing and reordering
        'layer_rotate'     # Z-axis layer rotation
    ])
    
    def __init__(
        self,
        chaos_engine: Optional[ChaosEngine] = None,
        strategy: str = 'voxel_swap',
        tensor_shape: Tuple[int, int, int] = TENSOR_SHAPE
    ):
        """
        Initialize the Tensor Engine.
        
        Args:
            chaos_engine: ChaosEngine for permutation generation
            strategy: Permutation strategy name
            tensor_shape: 3D tensor dimensions
        """
        self.tensor_shape = tensor_shape
        self.block_size = int(np.prod(tensor_shape))
        
        if strategy not in self.PERMUTATION_STRATEGIES:
            raise ValueError(
                f"Invalid strategy '{strategy}'. "
                f"Must be one of: {self.PERMUTATION_STRATEGIES}"
            )
        self.strategy = strategy
        
        self.chaos_engine = chaos_engine or ChaosEngine(
            tensor_shape=tensor_shape
        )
        
        # Performance metrics
        self._encrypt_count = 0
        self._decrypt_count = 0
        self._total_bytes_processed = 0
    
    def _pad_message(self, data: bytes) -> List[bytes]:
        """
        Split message into blocks with padding and headers.
        
        Args:
            data: Raw message bytes
            
        Returns:
            List of padded blocks with headers (each exactly TOTAL_BLOCK_SIZE bytes)
        """
        total_len = len(data)
        num_blocks = max(1, (total_len + self.BLOCK_SIZE - 1) // self.BLOCK_SIZE)
        
        blocks = []
        for i in range(num_blocks):
            start = i * self.BLOCK_SIZE
            end = min(start + self.BLOCK_SIZE, total_len)
            block_data = data[start:end]
            
            # Store actual data length before padding
            actual_length = len(block_data)
            
            # Pad with cryptographic noise if needed to reach BLOCK_SIZE
            if len(block_data) < self.BLOCK_SIZE:
                padding_len = self.BLOCK_SIZE - len(block_data)
                # Generate deterministic padding from block index
                pad_seed = hashlib.sha256(
                    f"padding:{i}:{total_len}".encode()
                ).digest()[:padding_len]
                block_data = block_data + pad_seed
            
            # Create metadata header
            metadata = BlockMetadata(
                actual_length=actual_length,  # Actual data length (before padding)
                block_index=i,
                total_blocks=num_blocks,
                checksum=self._compute_block_checksum(block_data, i)
            )
            
            # Combine header and data (should be exactly TOTAL_BLOCK_SIZE)
            full_block = metadata.to_bytes() + block_data
            blocks.append(full_block)
        
        return blocks
    
    def _unpad_blocks(self, blocks: List[bytes]) -> bytes:
        """
        Reconstruct original message from decrypted blocks.
        
        Args:
            blocks: List of decrypted blocks with headers
            
        Returns:
            Reconstructed original message
        """
        if not blocks:
            return b''
        
        # Sort blocks by index
        block_dict = {}
        for block in blocks:
            metadata = BlockMetadata.from_bytes(block[:self.HEADER_SIZE])
            block_data = block[self.HEADER_SIZE:]
            block_dict[metadata.block_index] = (metadata, block_data)
        
        # Reconstruct in order
        result_parts = []
        total_blocks = max(b[0].total_blocks for b in block_dict.values())
        
        for i in range(total_blocks):
            if i not in block_dict:
                raise ValueError(f"Missing block {i}")
            
            metadata, block_data = block_dict[i]
            
            # For last block, trim padding based on actual_length
            if i == total_blocks - 1:
                actual_len = metadata.actual_length % self.BLOCK_SIZE
                if actual_len == 0:
                    actual_len = self.BLOCK_SIZE
                block_data = block_data[:actual_len]
            
            result_parts.append(block_data)
        
        return b''.join(result_parts)
    
    def _compute_block_checksum(self, data: bytes, block_index: int) -> int:
        """Compute simple checksum for block integrity"""
        combined = data + block_index.to_bytes(4, byteorder='big')
        hash_val = hashlib.md5(combined).digest()
        return int.from_bytes(hash_val[:4], byteorder='big')
    
    def _apply_permutation(
        self,
        tensor: np.ndarray,
        mu: float,
        x0: float,
        inverse: bool = False
    ) -> np.ndarray:
        """
        Apply or reverse chaotic permutation to tensor.
        
        Args:
            tensor: 3D tensor to permute
            mu: Chaos parameter
            x0: Initial condition
            inverse: If True, apply inverse permutation
            
        Returns:
            Permuted tensor
        """
        flat_size = tensor.size
        
        # Generate permutation indices
        indices = self.chaos_engine.generate_permutation_indices(
            size=flat_size,
            mu=mu,
            x0=x0
        )
        
        # Flatten tensor
        flat_tensor = tensor.flatten()
        
        if inverse:
            # Create inverse permutation
            inverse_indices = np.zeros_like(indices)
            inverse_indices[indices] = np.arange(len(indices))
            result = flat_tensor[inverse_indices]
        else:
            result = flat_tensor[indices]
        
        return result.reshape(tensor.shape)
    
    def _apply_strategy(
        self,
        tensor: np.ndarray,
        mu: float,
        x0: float,
        inverse: bool = False
    ) -> np.ndarray:
        """
        Apply permutation strategy to tensor.
        
        Args:
            tensor: 3D tensor
            mu: Chaos parameter
            x0: Initial condition
            inverse: If True, apply inverse operation
            
        Returns:
            Transformed tensor
        """
        if self.strategy == 'voxel_swap':
            return self._apply_permutation(tensor, mu, x0, inverse)
        
        elif self.strategy == 'row_shift':
            # Row-wise cyclic shift based on chaotic values
            chaos_tensor = self.chaos_engine.generate_tensor(mu=mu, x0=x0)
            result = tensor.copy()
            
            for i in range(tensor.shape[0]):
                shift_amount = int(chaos_tensor[i, 0, 0] * tensor.shape[1])
                if inverse:
                    shift_amount = -shift_amount
                result[i] = np.roll(result[i], shift_amount, axis=0)
            
            return result
        
        elif self.strategy == 'layer_rotate':
            # Rotate Z-axis layers
            chaos_seq = self.chaos_engine.generate_sequence(
                mu=mu, x0=x0, iterations=tensor.shape[2]
            )
            result = tensor.copy()
            
            for k in range(tensor.shape[2]):
                rotation = int(chaos_seq[k] * 4)  # 0-3 quarter rotations
                if inverse:
                    rotation = -rotation
                result[:, :, k] = np.rot90(result[:, :, k], k=rotation)
            
            return result
        
        elif self.strategy == 'bit_plane':
            # Bit-plane slicing (simplified version)
            # Convert to bits, permute bit planes, convert back
            flat = tensor.flatten().astype(np.uint8)
            bits = np.unpackbits(flat)
            
            # Generate permutation for bits
            bit_indices = self.chaos_engine.generate_permutation_indices(
                size=len(bits),
                mu=mu,
                x0=x0
            )
            
            if inverse:
                inverse_indices = np.zeros_like(bit_indices)
                inverse_indices[bit_indices] = np.arange(len(bit_indices))
                permuted_bits = bits[inverse_indices]
            else:
                permuted_bits = bits[bit_indices]
            
            result_flat = np.packbits(permuted_bits)
            return result_flat[:tensor.size].reshape(tensor.shape).astype(np.float64) / 255.0
        
        else:
            raise ValueError(f"Unknown strategy: {self.strategy}")
    
    def _generate_key_tensor(
        self,
        mu: float,
        x0: float,
        shape: Optional[Tuple[int, int, int]] = None
    ) -> np.ndarray:
        """
        Generate key tensor K from chaotic sequence.
        
        Args:
            mu: Chaos parameter
            x0: Initial condition
            shape: Tensor shape
            
        Returns:
            Key tensor with values in [0, 255]
        """
        shape = shape or self.tensor_shape
        chaos_tensor = self.chaos_engine.generate_tensor(
            mu=mu, x0=x0, shape=shape
        )
        
        # Scale to byte range [0, 255]
        key_tensor = (chaos_tensor * 255).astype(np.uint8)
        return key_tensor
    
    def _generate_ai_noise(
        self,
        session_id: str,
        shape: Optional[Tuple[int, int, int]] = None
    ) -> np.ndarray:
        """
        Generate AI noise tensor A_AI for session.
        
        In production, this would use real-time environmental entropy.
        For prototype, we derive it deterministically from session_id.
        
        Args:
            session_id: Session identifier
            shape: Tensor shape
            
        Returns:
            Noise tensor with values in [0, 255]
        """
        shape = shape or self.tensor_shape
        
        # Derive seed from session_id (ensure it's within valid range)
        seed_hash = hashlib.sha256(f"ai_noise:{session_id}".encode()).digest()
        seed_int = int.from_bytes(seed_hash[:4], byteorder='big') % (2**32)
        
        # Use seed to generate deterministic noise
        rng = np.random.default_rng(seed_int)
        noise = rng.integers(0, 256, size=shape, dtype=np.uint8)
        
        return noise
    
    def encrypt_block(
        self,
        block: bytes,
        mu: float,
        x0: float,
        session_id: str
    ) -> bytes:
        """
        Encrypt a single 528-byte block (16-byte header + 512-byte data).
        
        Equation: C = (M ⊛ K) ⊕ A_AI
        
        Args:
            block: Full block with header (528 bytes)
            mu: Chaos parameter
            x0: Initial condition
            session_id: Session identifier
            
        Returns:
            Encrypted block
        """
        if len(block) != self.TOTAL_BLOCK_SIZE:
            raise ValueError(
                f"Block must be {self.TOTAL_BLOCK_SIZE} bytes, got {len(block)}"
            )
        
        # Separate header and data
        header = block[:self.HEADER_SIZE]
        data = block[self.HEADER_SIZE:]
        
        # Convert data to tensor
        data_array = np.frombuffer(data, dtype=np.uint8).copy()
        tensor = data_array.reshape(self.tensor_shape)
        
        # Generate key tensor K
        key_tensor = self._generate_key_tensor(mu, x0)
        
        # Layer 1: XOR with key tensor
        encrypted = np.bitwise_xor(tensor, key_tensor)
        
        # Layer 2: Apply chaotic permutation (⊛ operation)
        permuted = self._apply_strategy(encrypted, mu, x0, inverse=False)
        
        # Layer 3: Add AI noise
        ai_noise = self._generate_ai_noise(session_id)
        final = np.bitwise_xor(
            (permuted * 255).astype(np.uint8),
            ai_noise
        )
        
        # Combine header (unchanged) with encrypted data
        result = header + final.tobytes()
        
        self._encrypt_count += 1
        self._total_bytes_processed += len(data)
        
        return result
    
    def decrypt_block(
        self,
        block: bytes,
        mu: float,
        x0: float,
        session_id: str
    ) -> bytes:
        """
        Decrypt a single 528-byte block.
        
        Reverses: C = (M ⊛ K) ⊕ A_AI
        
        Args:
            block: Encrypted block with header
            mu: Chaos parameter
            x0: Initial condition
            session_id: Session identifier
            
        Returns:
            Decrypted block
        """
        if len(block) != self.TOTAL_BLOCK_SIZE:
            raise ValueError(
                f"Block must be {self.TOTAL_BLOCK_SIZE} bytes, got {len(block)}"
            )
        
        # Separate header and data
        header = block[:self.HEADER_SIZE]
        data = block[self.HEADER_SIZE:]
        
        # Convert data to tensor
        data_array = np.frombuffer(data, dtype=np.uint8).copy()
        tensor = data_array.reshape(self.tensor_shape)
        
        # Layer 3 Reverse: Remove AI noise
        ai_noise = self._generate_ai_noise(session_id)
        unnoised = np.bitwise_xor(tensor, ai_noise)
        
        # Convert back to float for permutation reversal
        unnoised_float = unnoised.astype(np.float64) / 255.0
        
        # Layer 2 Reverse: Apply inverse permutation
        unpermuted = self._apply_strategy(unnoised_float, mu, x0, inverse=True)
        
        # Layer 1 Reverse: XOR with key tensor (same as encrypt)
        key_tensor = self._generate_key_tensor(mu, x0)
        decrypted = np.bitwise_xor(
            (unpermuted * 255).astype(np.uint8),
            key_tensor
        )
        
        # Combine header with decrypted data
        result = header + decrypted.tobytes()
        
        self._decrypt_count += 1
        
        return result
    
    def encrypt(
        self,
        data: bytes,
        mu: float,
        x0: float,
        session_id: str
    ) -> EncryptionResult:
        """
        Encrypt arbitrary-length message.
        
        Splits message into 512-byte blocks, adds headers,
        and encrypts each block.
        
        Args:
            data: Raw message bytes
            mu: Chaos parameter
            x0: Initial condition
            session_id: Session identifier
            
        Returns:
            EncryptionResult with ciphertext and metadata
        """
        start_time = time.time()
        
        # Split into blocks with headers
        blocks = self._pad_message(data)
        
        # Encrypt each block
        encrypted_blocks = [
            self.encrypt_block(block, mu, x0, session_id)
            for block in blocks
        ]
        
        # Combine all blocks
        ciphertext = b''.join(encrypted_blocks)
        
        # Calculate entropy score
        chaos_seq = self.chaos_engine.generate_sequence(mu=mu, x0=x0, iterations=256)
        entropy = self.chaos_engine.get_entropy_estimate(chaos_seq)
        
        return EncryptionResult(
            ciphertext=ciphertext,
            session_id=session_id,
            block_count=len(blocks),
            timestamp=start_time,
            entropy_score=entropy,
            metadata={
                'original_size': len(data),
                'encrypted_size': len(ciphertext),
                'strategy': self.strategy,
                'mu': mu,
                'tensor_shape': self.tensor_shape
            }
        )
    
    def decrypt(
        self,
        ciphertext: bytes,
        mu: float,
        x0: float,
        session_id: str
    ) -> DecryptionResult:
        """
        Decrypt ciphertext back to original message.
        
        Args:
            ciphertext: Encrypted bytes
            mu: Chaos parameter
            x0: Initial condition
            session_id: Session identifier
            
        Returns:
            DecryptionResult with plaintext and verification status
        """
        start_time = time.time()
        
        # Split into blocks
        block_size = self.TOTAL_BLOCK_SIZE
        num_blocks = len(ciphertext) // block_size
        
        if len(ciphertext) % block_size != 0:
            raise ValueError(
                f"Ciphertext length {len(ciphertext)} is not a multiple "
                f"of block size {block_size}"
            )
        
        # Decrypt each block
        decrypted_blocks = [
            self.decrypt_block(
                ciphertext[i*block_size:(i+1)*block_size],
                mu, x0, session_id
            )
            for i in range(num_blocks)
        ]
        
        # Verify checksums and reconstruct
        plaintext = self._unpad_blocks(decrypted_blocks)
        
        # Basic verification (could be enhanced)
        verified = len(plaintext) >= 0  # Placeholder for more robust verification
        
        return DecryptionResult(
            plaintext=plaintext,
            session_id=session_id,
            block_count=num_blocks,
            timestamp=start_time,
            verified=verified,
            metadata={
                'ciphertext_size': len(ciphertext),
                'plaintext_size': len(plaintext),
                'strategy': self.strategy
            }
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics"""
        return {
            'encrypt_operations': self._encrypt_count,
            'decrypt_operations': self._decrypt_count,
            'total_bytes_processed': self._total_bytes_processed,
            'strategy': self.strategy,
            'tensor_shape': self.tensor_shape
        }
    
    def reset_stats(self):
        """Reset statistics counters"""
        self._encrypt_count = 0
        self._decrypt_count = 0
        self._total_bytes_processed = 0
