"""
tensor_engine.py
Core tensor-based encryption engine for post-quantum cryptography

This module implements the foundational tensor-based encryption and decryption
operations for the quantum-resistant IPsec alternative system.
"""

import numpy as np
import hashlib
import hmac
import os
import pickle
import logging
from datetime import datetime
from typing import Tuple, Optional, Dict, Any
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class TensorEncryptionEngine:
    """
    Core tensor-based encryption engine implementing quantum-resistant cryptography
    using high-dimensional tensor operations and nonlinear transformations.
    """
    
    def __init__(self, tensor_dimensions: Tuple[int, int] = (8, 8), 
                 dtype: np.dtype = np.int8,
                 security_level: str = 'standard'):
        """
        Initialize tensor encryption engine
        
        Args:
            tensor_dimensions: Shape of encryption tensors (default: 8x8)
            dtype: Data type for tensor operations (default: int8)
            security_level: 'basic', 'standard', or 'high' (affects key complexity)
        """
        self.tensor_dims = tensor_dimensions
        self.dtype = dtype
        self.security_level = security_level
        self.tensor_size = np.prod(tensor_dimensions)
        
        # Initialize logging
        self.logger = logging.getLogger(__name__)
        
        # Security parameters based on level
        self.security_params = self._get_security_parameters(security_level)
        
        # Transformation history for analysis
        self.transformation_history = []
        
        # Initialize master tensor
        self.master_tensor = self._generate_master_tensor()
        
    def _get_security_parameters(self, level: str) -> Dict[str, Any]:
        """Get security parameters based on security level"""
        params = {
            'basic': {
                'pbkdf2_iterations': 10000,
                'nonlinear_layers': 2,
                'permutation_rounds': 1,
                'entropy_threshold': 6.0
            },
            'standard': {
                'pbkdf2_iterations': 50000,
                'nonlinear_layers': 3,
                'permutation_rounds': 2,
                'entropy_threshold': 6.5
            },
            'high': {
                'pbkdf2_iterations': 100000,
                'nonlinear_layers': 4,
                'permutation_rounds': 3,
                'entropy_threshold': 7.0
            }
        }
        return params.get(level, params['standard'])
    
    def _generate_master_tensor(self) -> np.ndarray:
        """Generate cryptographically secure master tensor"""
        # Use cryptographic random number generator
        random_seed = os.urandom(64)
        
        # Create deterministic but unpredictable seed
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'tensor_crypto_master_salt_2025',
            iterations=self.security_params['pbkdf2_iterations']
        )
        
        key = kdf.derive(random_seed)
        np.random.seed(int.from_bytes(key[:4], 'big'))
        
        # Generate high-entropy tensor
        master = np.random.uniform(-128, 127, self.tensor_dims).astype(self.dtype)
        
        # Apply cryptographic transformations
        master = self._apply_cryptographic_transformations(master)
        
        self.logger.info(f"Master tensor generated with dimensions {self.tensor_dims}")
        return master
    
    def _apply_cryptographic_transformations(self, tensor: np.ndarray) -> np.ndarray:
        """Apply cryptographic transformations to enhance security"""
        result = tensor.copy()
        
        # Multiple rounds of nonlinear transformations
        for round_num in range(self.security_params['nonlinear_layers']):
            # Nonlinear function based on tensor values
            result = np.where(result >= 0,
                            (result * 3) % 256 - 128,
                            (result * 5) % 256 - 128)
            
            # Bit rotation based on position
            for i in range(result.shape[0]):
                for j in range(result.shape[1]):
                    rotation = (i + j + round_num) % 8
                    result[i, j] = self._rotate_bits(result[i, j], rotation)
        
        return result.astype(self.dtype)
    
    def _rotate_bits(self, value: int, rotation: int) -> int:
        """Rotate bits of an 8-bit value"""
        # Convert to unsigned 8-bit
        unsigned_val = value & 0xFF
        # Rotate left
        rotated = ((unsigned_val << rotation) | (unsigned_val >> (8 - rotation))) & 0xFF
        # Convert back to signed
        return rotated if rotated < 128 else rotated - 256
    
    def generate_session_tensor(self, session_id: str, 
                              device_fingerprint: str,
                              additional_entropy: Optional[bytes] = None) -> np.ndarray:
        """
        Generate deterministic but unpredictable tensor for session
        
        Args:
            session_id: Unique session identifier
            device_fingerprint: Device-specific fingerprint
            additional_entropy: Optional additional entropy source
            
        Returns:
            Session-specific tensor key
        """
        # Combine inputs for seed generation
        seed_data = f"{session_id}_{device_fingerprint}".encode()
        if additional_entropy:
            seed_data += additional_entropy
        
        # Create cryptographically strong seed
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,
            salt=b'tensor_session_salt_2025',
            iterations=self.security_params['pbkdf2_iterations']
        )
        
        session_key = kdf.derive(seed_data)
        
        # Generate session tensor
        np.random.seed(int.from_bytes(session_key[:4], 'big'))
        session_tensor = np.random.randint(-128, 127, self.tensor_dims, dtype=self.dtype)
        
        # Apply tensor product with master tensor for additional security
        enhanced_tensor = self._tensor_product_operation(session_tensor, self.master_tensor)
        
        # Apply session-specific transformations
        final_tensor = self._apply_session_transformations(enhanced_tensor, session_key)
        
        self.logger.debug(f"Session tensor generated for session: {session_id}")
        return final_tensor
    
    def _tensor_product_operation(self, tensor_a: np.ndarray, 
                                 tensor_b: np.ndarray) -> np.ndarray:
        """Perform tensor product operation for key mixing"""
        # Element-wise operations
        mixed = np.bitwise_xor(tensor_a.astype(np.uint8), tensor_b.astype(np.uint8))
        
        # Matrix-like operations if dimensions allow
        if tensor_a.shape[0] == tensor_b.shape[1]:
            matrix_product = np.matmul(tensor_a.astype(np.float32), 
                                     tensor_b.astype(np.float32))
            # Normalize and convert back
            normalized = ((matrix_product % 256) - 128).astype(self.dtype)
            mixed = np.bitwise_xor(mixed, normalized.astype(np.uint8))
        
        return mixed.astype(self.dtype)
    
    def _apply_session_transformations(self, tensor: np.ndarray, 
                                     session_key: bytes) -> np.ndarray:
        """Apply session-specific transformations"""
        result = tensor.copy()
        
        # Use session key to determine transformation parameters
        transform_params = np.frombuffer(session_key[:16], dtype=np.uint8)
        
        # Apply permutations
        for round_num in range(self.security_params['permutation_rounds']):
            perm_seed = transform_params[round_num % len(transform_params)]
            result = self._apply_permutation(result, perm_seed)
        
        return result
    
    def _apply_permutation(self, tensor: np.ndarray, seed: int) -> np.ndarray:
        """Apply deterministic permutation based on seed"""
        np.random.seed(seed)
        
        # Row permutation
        row_perm = np.random.permutation(tensor.shape[0])
        permuted = tensor[row_perm]
        
        # Column permutation
        col_perm = np.random.permutation(tensor.shape[1])
        permuted = permuted[:, col_perm]
        
        return permuted
    
    def encrypt_data(self, data: bytes, encryption_tensor: np.ndarray,
                    nonce: Optional[bytes] = None) -> Tuple[bytes, Dict[str, Any]]:
        """
        Encrypt data using tensor operations
        
        Args:
            data: Input data to encrypt
            encryption_tensor: Tensor key for encryption
            nonce: Optional nonce for additional security
            
        Returns:
            Tuple of (encrypted_data, metadata)
        """
        if nonce is None:
            nonce = os.urandom(16)
        
        # Prepare data for tensor operations
        padded_data, original_length = self._prepare_data_for_encryption(data, nonce)
        
        # Convert to tensor format
        data_tensor = self._bytes_to_tensor(padded_data)
        
        # Apply multi-layer tensor encryption
        encrypted_tensor = self._apply_encryption_layers(data_tensor, encryption_tensor)
        
        # Convert back to bytes
        encrypted_bytes = self._tensor_to_bytes(encrypted_tensor)
        
        # Create metadata for decryption
        metadata = {
            'nonce': nonce,
            'original_length': original_length,
            'tensor_hash': hashlib.sha256(encryption_tensor.tobytes()).hexdigest(),
            'encryption_timestamp': datetime.now().isoformat(),
            'tensor_dimensions': self.tensor_dims
        }
        
        # Log transformation for analysis
        self.transformation_history.append({
            'operation': 'encrypt',
            'timestamp': datetime.now(),
            'data_length': len(data),
            'tensor_hash': metadata['tensor_hash']
        })
        
        return encrypted_bytes, metadata
    
    def decrypt_data(self, encrypted_data: bytes, decryption_tensor: np.ndarray,
                    metadata: Dict[str, Any]) -> bytes:
        """
        Decrypt data using inverse tensor operations
        
        Args:
            encrypted_data: Encrypted data bytes
            decryption_tensor: Tensor key for decryption
            metadata: Metadata from encryption process
            
        Returns:
            Original decrypted data
        """
        # Verify tensor compatibility
        expected_hash = hashlib.sha256(decryption_tensor.tobytes()).hexdigest()
        if expected_hash != metadata['tensor_hash']:
            raise ValueError("Tensor key mismatch - decryption not possible")
        
        # Convert encrypted bytes to tensor
        encrypted_tensor = self._bytes_to_tensor(encrypted_data)
        
        # Apply inverse encryption layers
        decrypted_tensor = self._apply_decryption_layers(encrypted_tensor, decryption_tensor)
        
        # Convert back to bytes
        decrypted_bytes = self._tensor_to_bytes(decrypted_tensor)
        
        # Extract original data
        original_data = self._extract_original_data(
            decrypted_bytes, metadata['nonce'], metadata['original_length']
        )
        
        # Log transformation
        self.transformation_history.append({
            'operation': 'decrypt',
            'timestamp': datetime.now(),
            'data_length': len(original_data),
            'tensor_hash': metadata['tensor_hash']
        })
        
        return original_data
    
    def _prepare_data_for_encryption(self, data: bytes, 
                                   nonce: bytes) -> Tuple[bytes, int]:
        """Prepare data for tensor encryption"""
        original_length = len(data)
        
        # Prepend nonce and length information
        length_bytes = original_length.to_bytes(4, 'big')
        combined_data = nonce + length_bytes + data
        
        # Pad to tensor size
        if len(combined_data) < self.tensor_size:
            padding_needed = self.tensor_size - len(combined_data)
            padding = os.urandom(padding_needed)
            combined_data += padding
        elif len(combined_data) > self.tensor_size:
            # For larger data, use chunking (simplified for demo)
            combined_data = combined_data[:self.tensor_size]
        
        return combined_data, original_length
    
    def _extract_original_data(self, decrypted_bytes: bytes, 
                             expected_nonce: bytes, original_length: int) -> bytes:
        """Extract original data from decrypted bytes"""
        nonce_size = len(expected_nonce)
        
        # Extract nonce and verify
        extracted_nonce = decrypted_bytes[:nonce_size]
        if extracted_nonce != expected_nonce:
            raise ValueError("Nonce verification failed - data may be corrupted")
        
        # Extract length
        length_bytes = decrypted_bytes[nonce_size:nonce_size + 4]
        extracted_length = int.from_bytes(length_bytes, 'big')
        
        if extracted_length != original_length:
            self.logger.warning("Length mismatch detected during decryption")
        
        # Extract original data
        data_start = nonce_size + 4
        data_end = data_start + original_length
        original_data = decrypted_bytes[data_start:data_end]
        
        return original_data
    
    def _bytes_to_tensor(self, data: bytes) -> np.ndarray:
        """Convert bytes to tensor format"""
        # Convert bytes to numpy array
        byte_array = np.frombuffer(data, dtype=np.uint8)
        
        # Pad or truncate to tensor size
        if len(byte_array) < self.tensor_size:
            padded = np.zeros(self.tensor_size, dtype=np.uint8)
            padded[:len(byte_array)] = byte_array
            byte_array = padded
        elif len(byte_array) > self.tensor_size:
            byte_array = byte_array[:self.tensor_size]
        
        # Reshape to tensor dimensions and convert to signed
        tensor = byte_array.reshape(self.tensor_dims).astype(self.dtype)
        return tensor
    
    def _tensor_to_bytes(self, tensor: np.ndarray) -> bytes:
        """Convert tensor to bytes format"""
        # Convert to unsigned bytes
        unsigned_tensor = tensor.astype(np.uint8)
        return unsigned_tensor.flatten().tobytes()
    
    def _apply_encryption_layers(self, data_tensor: np.ndarray, 
                               key_tensor: np.ndarray) -> np.ndarray:
        """Apply multiple encryption layers"""
        result = data_tensor.copy()
        
        # Layer 1: Basic XOR with key
        result = np.bitwise_xor(result.astype(np.uint8), 
                               key_tensor.astype(np.uint8)).astype(self.dtype)
        
        # Layer 2: Nonlinear transformation
        result = self._nonlinear_transformation(result, key_tensor)
        
        # Layer 3: Tensor permutation
        result = self._tensor_permutation(result, key_tensor)
        
        # Layer 4: Advanced mixing
        result = self._advanced_tensor_mixing(result, key_tensor)
        
        return result
    
    def _apply_decryption_layers(self, encrypted_tensor: np.ndarray, 
                               key_tensor: np.ndarray) -> np.ndarray:
        """Apply inverse decryption layers"""
        result = encrypted_tensor.copy()
        
        # Reverse Layer 4: Inverse advanced mixing
        result = self._inverse_advanced_tensor_mixing(result, key_tensor)
        
        # Reverse Layer 3: Inverse tensor permutation
        result = self._inverse_tensor_permutation(result, key_tensor)
        
        # Reverse Layer 2: Inverse nonlinear transformation
        result = self._inverse_nonlinear_transformation(result, key_tensor)
        
        # Reverse Layer 1: XOR with key
        result = np.bitwise_xor(result.astype(np.uint8), 
                               key_tensor.astype(np.uint8)).astype(self.dtype)
        
        return result
    
    def _nonlinear_transformation(self, data_tensor: np.ndarray, 
                                 key_tensor: np.ndarray) -> np.ndarray:
        """Apply nonlinear transformation based on key"""
        result = data_tensor.copy()
        
        # Use key values to determine transformation parameters
        for i in range(result.shape[0]):
            for j in range(result.shape[1]):
                key_val = key_tensor[i, j]
                data_val = result[i, j]
                
                # Nonlinear function based on key
                if key_val >= 0:
                    transformed = ((data_val * 3) + key_val) % 256
                else:
                    transformed = ((data_val * 5) - key_val) % 256
                
                result[i, j] = transformed if transformed < 128 else transformed - 256
        
        return result.astype(self.dtype)
    
    def _inverse_nonlinear_transformation(self, transformed_tensor: np.ndarray, 
                                        key_tensor: np.ndarray) -> np.ndarray:
        """Apply inverse nonlinear transformation"""
        result = transformed_tensor.copy()
        
        for i in range(result.shape[0]):
            for j in range(result.shape[1]):
                key_val = key_tensor[i, j]
                transformed_val = result[i, j]
                
                # Convert to unsigned for modular arithmetic
                unsigned_val = transformed_val & 0xFF
                                
                # Inverse transformation
                if key_val >= 0:
                    # Inverse of ((data_val * 3) + key_val) % 256
                    original = ((unsigned_val - key_val) * pow(3, -1, 256)) % 256
                else:
                    # Inverse of ((data_val * 5) - key_val) % 256
                    original = ((unsigned_val + key_val) * pow(5, -1, 256)) % 256
                
                result[i, j] = original if original < 128 else original - 256
        
        return result.astype(self.dtype)
    
    def _tensor_permutation(self, data_tensor: np.ndarray, 
                          key_tensor: np.ndarray) -> np.ndarray:
        """Apply tensor permutation based on key"""
        result = data_tensor.copy()
        
        # Create permutation indices from key
        key_sum = np.sum(key_tensor, axis=1) % result.shape[0]
        row_perm = np.argsort(key_sum)
        
        key_sum_col = np.sum(key_tensor, axis=0) % result.shape[1]
        col_perm = np.argsort(key_sum_col)
        
        # Apply permutations
        result = result[row_perm]
        result = result[:, col_perm]
        
        return result
    
    def _inverse_tensor_permutation(self, permuted_tensor: np.ndarray, 
                                  key_tensor: np.ndarray) -> np.ndarray:
        """Apply inverse tensor permutation"""
        result = permuted_tensor.copy()
        
        # Create same permutation indices from key
        key_sum = np.sum(key_tensor, axis=1) % result.shape[0]
        row_perm = np.argsort(key_sum)
        inverse_row_perm = np.argsort(row_perm)
        
        key_sum_col = np.sum(key_tensor, axis=0) % result.shape[1]
        col_perm = np.argsort(key_sum_col)
        inverse_col_perm = np.argsort(col_perm)
        
        # Apply inverse permutations
        result = result[:, inverse_col_perm]
        result = result[inverse_row_perm]
        
        return result
    
    def _advanced_tensor_mixing(self, data_tensor: np.ndarray, 
                              key_tensor: np.ndarray) -> np.ndarray:
        """Apply advanced tensor mixing operations"""
        result = data_tensor.copy()
        
        # Circular shift based on key
        for i in range(result.shape[0]):
            shift_amount = abs(key_tensor[i, 0]) % result.shape[1]
            result[i] = np.roll(result[i], shift_amount)
        
        # XOR with transformed key
        transformed_key = np.rot90(key_tensor)
        result = np.bitwise_xor(result.astype(np.uint8), 
                               transformed_key.astype(np.uint8))
        
        return result.astype(self.dtype)
    
    def _inverse_advanced_tensor_mixing(self, mixed_tensor: np.ndarray, 
                                      key_tensor: np.ndarray) -> np.ndarray:
        """Apply inverse advanced tensor mixing"""
        result = mixed_tensor.copy()
        
        # Reverse XOR with transformed key
        transformed_key = np.rot90(key_tensor)
        result = np.bitwise_xor(result.astype(np.uint8), 
                               transformed_key.astype(np.uint8))
        
        # Reverse circular shift
        for i in range(result.shape[0]):
            shift_amount = abs(key_tensor[i, 0]) % result.shape[1]
            result[i] = np.roll(result[i], -shift_amount)
        
        return result.astype(self.dtype)
    
    def verify_tensor_integrity(self, tensor: np.ndarray) -> bool:
        """Verify tensor integrity and properties"""
        if tensor.shape != self.tensor_dims:
            return False
        
        if tensor.dtype != self.dtype:
            return False
        
        # Check for reasonable entropy
        unique_values = len(np.unique(tensor))
        expected_min_unique = max(4, self.tensor_size // 4)
        
        if unique_values < expected_min_unique:
            self.logger.warning(f"Low entropy detected: {unique_values} unique values")
            return False
        
        return True
    
    def get_encryption_metrics(self) -> Dict[str, Any]:
        """Get encryption engine metrics and statistics"""
        if not self.transformation_history:
            return {'total_operations': 0}
        
        encrypt_ops = sum(1 for op in self.transformation_history 
                         if op['operation'] == 'encrypt')
        decrypt_ops = sum(1 for op in self.transformation_history 
                         if op['operation'] == 'decrypt')
        
        total_data_encrypted = sum(op['data_length'] for op in self.transformation_history 
                                 if op['operation'] == 'encrypt')
        
        return {
            'total_operations': len(self.transformation_history),
            'encrypt_operations': encrypt_ops,
            'decrypt_operations': decrypt_ops,
            'total_data_encrypted': total_data_encrypted,
            'tensor_dimensions': self.tensor_dims,
            'security_level': self.security_level,
            'unique_sessions': len(set(op['tensor_hash'] for op in self.transformation_history))
        }
    
    def export_tensor_key(self, tensor: np.ndarray, password: str) -> bytes:
        """Export tensor key in encrypted format"""
        # Serialize tensor
        tensor_bytes = pickle.dumps(tensor)
        
        # Encrypt with password
        password_bytes = password.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'tensor_export_salt',
            iterations=100000
        )
        key = kdf.derive(password_bytes)
        
        # Simple XOR encryption for export (in practice, use AES)
        key_repeated = np.tile(key, (len(tensor_bytes) // len(key)) + 1)[:len(tensor_bytes)]
        encrypted_bytes = bytes(a ^ b for a, b in zip(tensor_bytes, key_repeated))
        
        return encrypted_bytes
    
    def import_tensor_key(self, encrypted_data: bytes, password: str) -> np.ndarray:
        """Import tensor key from encrypted format"""
        # Derive key from password
        password_bytes = password.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'tensor_export_salt',
            iterations=100000
        )
        key = kdf.derive(password_bytes)
        
        # Decrypt
        key_repeated = np.tile(key, (len(encrypted_data) // len(key)) + 1)[:len(encrypted_data)]
        decrypted_bytes = bytes(a ^ b for a, b in zip(encrypted_data, key_repeated))
        
        # Deserialize tensor
        tensor = pickle.loads(decrypted_bytes)
        
        # Verify tensor
        if not self.verify_tensor_integrity(tensor):
            raise ValueError("Imported tensor failed integrity check")
        
        return tensor
    
    def benchmark_performance(self, num_iterations: int = 1000) -> Dict[str, float]:
        """Benchmark encryption/decryption performance"""
        import time
        
        # Generate test data
        test_data = b"Performance benchmark test data for tensor encryption engine"
        session_tensor = self.generate_session_tensor("benchmark_session", "benchmark_device")
        
        # Benchmark encryption
        start_time = time.time()
        for _ in range(num_iterations):
            encrypted_data, metadata = self.encrypt_data(test_data, session_tensor)
        encrypt_time = time.time() - start_time
        
        # Benchmark decryption
        start_time = time.time()
        for _ in range(num_iterations):
            decrypted_data = self.decrypt_data(encrypted_data, session_tensor, metadata)
        decrypt_time = time.time() - start_time
        
        return {
            'iterations': num_iterations,
            'encrypt_time_total': encrypt_time,
            'decrypt_time_total': decrypt_time,
            'encrypt_ops_per_sec': num_iterations / encrypt_time,
            'decrypt_ops_per_sec': num_iterations / decrypt_time,
            'encrypt_time_per_op_ms': (encrypt_time / num_iterations) * 1000,
            'decrypt_time_per_op_ms': (decrypt_time / num_iterations) * 1000
        }
    
    def clear_history(self):
        """Clear transformation history"""
        self.transformation_history.clear()
        self.logger.info("Transformation history cleared")
    
    def __repr__(self) -> str:
        """String representation of the engine"""
        return (f"TensorEncryptionEngine(dims={self.tensor_dims}, "
                f"security='{self.security_level}', "
                f"operations={len(self.transformation_history)})")
