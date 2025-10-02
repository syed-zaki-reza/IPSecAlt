"""
test_tensor_engine.py
Comprehensive test suite for the tensor encryption engine

Tests cover:
- Basic encryption/decryption functionality
- Security properties and edge cases
- Performance and reliability
- Integration scenarios
"""

import unittest
import numpy as np
import hashlib
import os
import tempfile
import time
from unittest.mock import patch, MagicMock

# Import the module to test
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from tensor_engine import TensorEncryptionEngine


class TestTensorEncryptionEngine(unittest.TestCase):
    """Test suite for TensorEncryptionEngine class"""
    
    def setUp(self):
        """Set up test environment before each test"""
        self.engine = TensorEncryptionEngine(
            tensor_dimensions=(4, 4),
            security_level='standard'
        )
        self.test_data = b"Hello, this is a test message for encryption!"
        self.session_id = "test_session_123"
        self.device_fingerprint = "test_device_abc"
    
    def tearDown(self):
        """Clean up after each test"""
        # Clear transformation history
        self.engine.transformation_history.clear()
    
    def test_initialization(self):
        """Test engine initialization"""
        self.assertEqual(self.engine.tensor_dims, (4, 4))
        self.assertEqual(self.engine.tensor_size, 16)
        self.assertEqual(self.engine.security_level, 'standard')
        self.assertIsNotNone(self.engine.master_tensor)
        self.assertEqual(self.engine.master_tensor.shape, (4, 4))
    
    def test_security_levels(self):
        """Test different security levels"""
        basic_engine = TensorEncryptionEngine(security_level='basic')
        high_engine = TensorEncryptionEngine(security_level='high')
        
        # Check different parameters are set
        self.assertLess(basic_engine.security_params['pbkdf2_iterations'],
                       high_engine.security_params['pbkdf2_iterations'])
        self.assertLess(basic_engine.security_params['nonlinear_layers'],
                       high_engine.security_params['nonlinear_layers'])
    
    def test_master_tensor_generation(self):
        """Test master tensor generation"""
        master1 = self.engine._generate_master_tensor()
        master2 = self.engine._generate_master_tensor()
        
        # Master tensors should be different (cryptographically random)
        self.assertFalse(np.array_equal(master1, master2))
        
        # But should have correct shape and type
        self.assertEqual(master1.shape, self.engine.tensor_dims)
        self.assertEqual(master1.dtype, self.engine.dtype)
    
    def test_session_tensor_generation(self):
        """Test session tensor generation"""
        tensor1 = self.engine.generate_session_tensor(
            self.session_id, self.device_fingerprint
        )
        
        # Should have correct properties
        self.assertEqual(tensor1.shape, self.engine.tensor_dims)
        self.assertEqual(tensor1.dtype, self.engine.dtype)
        
        # Same parameters should generate same tensor (deterministic)
        tensor2 = self.engine.generate_session_tensor(
            self.session_id, self.device_fingerprint
        )
        self.assertTrue(np.array_equal(tensor1, tensor2))
        
        # Different parameters should generate different tensors
        tensor3 = self.engine.generate_session_tensor(
            "different_session", self.device_fingerprint
        )
        self.assertFalse(np.array_equal(tensor1, tensor3))
    
    def test_basic_encryption_decryption(self):
        """Test basic encryption and decryption"""
        # Generate session tensor
        session_tensor = self.engine.generate_session_tensor(
            self.session_id, self.device_fingerprint
        )
        
        # Encrypt data
        encrypted_data, metadata = self.engine.encrypt_data(
            self.test_data, session_tensor
        )
        
        # Check encryption result
        self.assertIsInstance(encrypted_data, bytes)
        self.assertIsInstance(metadata, dict)
        self.assertIn('nonce', metadata)
        self.assertIn('original_length', metadata)
        self.assertIn('tensor_hash', metadata)
        
        # Decrypt data
        decrypted_data = self.engine.decrypt_data(
            encrypted_data, session_tensor, metadata
        )
        
        # Check decryption result
        self.assertEqual(decrypted_data, self.test_data)
    
    def test_encryption_with_custom_nonce(self):
        """Test encryption with custom nonce"""
        session_tensor = self.engine.generate_session_tensor(
            self.session_id, self.device_fingerprint
        )
        
        custom_nonce = b"custom_nonce_16b"
        encrypted_data, metadata = self.engine.encrypt_data(
            self.test_data, session_tensor, nonce=custom_nonce
        )
        
        self.assertEqual(metadata['nonce'], custom_nonce)
        
        # Decryption should still work
        decrypted_data = self.engine.decrypt_data(
            encrypted_data, session_tensor, metadata
        )
        self.assertEqual(decrypted_data, self.test_data)
        
    def test_different_data_sizes(self):
        """Test encryption/decryption with different data sizes"""
        session_tensor = self.engine.generate_session_tensor(
            self.session_id, self.device_fingerprint
        )
        
        test_cases = [
            b"Short",                    # Very short message
            b"Medium length test message for encryption",  # Medium message
            b"A" * 100,                 # Long message (will be truncated)
            b"",                        # Empty message
            b"\x00\x01\x02\x03\x04",   # Binary data
        ]
        
        for test_data in test_cases:
            with self.subTest(data_length=len(test_data)):
                encrypted_data, metadata = self.engine.encrypt_data(
                    test_data, session_tensor
                )
                decrypted_data = self.engine.decrypt_data(
                    encrypted_data, session_tensor, metadata
                )
                
                # For data larger than tensor size, it gets truncated
                max_data_size = self.engine.tensor_size - 16 - 4  # nonce + length
                expected_data = test_data[:max_data_size] if len(test_data) > max_data_size else test_data
                self.assertEqual(decrypted_data, expected_data)
    
    def test_tensor_integrity_verification(self):
        """Test tensor integrity verification"""
        # Valid tensor
        valid_tensor = np.random.randint(-128, 127, self.engine.tensor_dims, dtype=np.int8)
        self.assertTrue(self.engine.verify_tensor_integrity(valid_tensor))
        
        # Invalid shape
        invalid_shape = np.random.randint(-128, 127, (3, 3), dtype=np.int8)
        self.assertFalse(self.engine.verify_tensor_integrity(invalid_shape))
        
        # Invalid dtype
        invalid_dtype = np.random.randint(-128, 127, self.engine.tensor_dims, dtype=np.int16)
        self.assertFalse(self.engine.verify_tensor_integrity(invalid_dtype))
        
        # Low entropy tensor (all same values)
        low_entropy = np.full(self.engine.tensor_dims, 42, dtype=np.int8)
        self.assertFalse(self.engine.verify_tensor_integrity(low_entropy))
    
    def test_wrong_key_decryption(self):
        """Test that wrong key fails decryption"""
        session_tensor = self.engine.generate_session_tensor(
            self.session_id, self.device_fingerprint
        )
        wrong_tensor = self.engine.generate_session_tensor(
            "wrong_session", self.device_fingerprint
        )
        
        # Encrypt with correct key
        encrypted_data, metadata = self.engine.encrypt_data(
            self.test_data, session_tensor
        )
        
        # Try to decrypt with wrong key
        with self.assertRaises(ValueError):
            self.engine.decrypt_data(encrypted_data, wrong_tensor, metadata)
    
    def test_corrupted_metadata(self):
        """Test handling of corrupted metadata"""
        session_tensor = self.engine.generate_session_tensor(
            self.session_id, self.device_fingerprint
        )
        
        encrypted_data, metadata = self.engine.encrypt_data(
            self.test_data, session_tensor
        )
        
        # Corrupt tensor hash
        corrupted_metadata = metadata.copy()
        corrupted_metadata['tensor_hash'] = "invalid_hash"
        
        with self.assertRaises(ValueError):
            self.engine.decrypt_data(encrypted_data, session_tensor, corrupted_metadata)
    
    def test_nonce_verification(self):
        """Test nonce verification during decryption"""
        session_tensor = self.engine.generate_session_tensor(
            self.session_id, self.device_fingerprint
        )
        
        encrypted_data, metadata = self.engine.encrypt_data(
            self.test_data, session_tensor
        )
        
        # Corrupt encrypted data (which contains nonce)
        corrupted_data = bytearray(encrypted_data)
        corrupted_data[0] = (corrupted_data[0] + 1) % 256  # Change first byte
        
        with self.assertRaises(ValueError):
            self.engine.decrypt_data(bytes(corrupted_data), session_tensor, metadata)
    
    def test_additional_entropy(self):
        """Test session tensor generation with additional entropy"""
        additional_entropy = b"extra_random_data_12345"
        
        tensor1 = self.engine.generate_session_tensor(
            self.session_id, self.device_fingerprint, additional_entropy
        )
        tensor2 = self.engine.generate_session_tensor(
            self.session_id, self.device_fingerprint, additional_entropy
        )
        tensor3 = self.engine.generate_session_tensor(
            self.session_id, self.device_fingerprint, b"different_entropy"
        )
        
        # Same entropy should produce same tensor
        self.assertTrue(np.array_equal(tensor1, tensor2))
        
        # Different entropy should produce different tensor
        self.assertFalse(np.array_equal(tensor1, tensor3))
    
    def test_transformation_history(self):
        """Test transformation history logging"""
        session_tensor = self.engine.generate_session_tensor(
            self.session_id, self.device_fingerprint
        )
        
        initial_count = len(self.engine.transformation_history)
        
        # Perform encryption
        encrypted_data, metadata = self.engine.encrypt_data(
            self.test_data, session_tensor
        )
        
        # Check history updated
        self.assertEqual(len(self.engine.transformation_history), initial_count + 1)
        self.assertEqual(self.engine.transformation_history[-1]['operation'], 'encrypt')
        
        # Perform decryption
        decrypted_data = self.engine.decrypt_data(
            encrypted_data, session_tensor, metadata
        )
        
        # Check history updated again
        self.assertEqual(len(self.engine.transformation_history), initial_count + 2)
        self.assertEqual(self.engine.transformation_history[-1]['operation'], 'decrypt')
    
    def test_encryption_metrics(self):
        """Test encryption metrics collection"""
        session_tensor = self.engine.generate_session_tensor(
            self.session_id, self.device_fingerprint
        )
        
        # Perform several operations
        for i in range(3):
            encrypted_data, metadata = self.engine.encrypt_data(
                f"Test message {i}".encode(), session_tensor
            )
            self.engine.decrypt_data(encrypted_data, session_tensor, metadata)
        
        metrics = self.engine.get_encryption_metrics()
        
        self.assertEqual(metrics['encrypt_operations'], 3)
        self.assertEqual(metrics['decrypt_operations'], 3)
        self.assertEqual(metrics['total_operations'], 6)
        self.assertGreater(metrics['total_data_encrypted'], 0)
        self.assertEqual(metrics['tensor_dimensions'], self.engine.tensor_dims)
        self.assertEqual(metrics['security_level'], 'standard')
    
    def test_key_export_import(self):
        """Test tensor key export and import functionality"""
        session_tensor = self.engine.generate_session_tensor(
            self.session_id, self.device_fingerprint
        )
        
        password = "test_password_123"
        
        # Export key
        exported_data = self.engine.export_tensor_key(session_tensor, password)
        self.assertIsInstance(exported_data, bytes)
        self.assertGreater(len(exported_data), 0)
        
        # Import key
        imported_tensor = self.engine.import_tensor_key(exported_data, password)
        
        # Verify imported key matches original
        self.assertTrue(np.array_equal(session_tensor, imported_tensor))
        
        # Test wrong password fails
        with self.assertRaises(Exception):
            self.engine.import_tensor_key(exported_data, "wrong_password")
    
    def test_performance_benchmark(self):
        """Test performance benchmarking functionality"""
        # Run small benchmark
        results = self.engine.benchmark_performance(num_iterations=10)
        
        # Check results structure
        self.assertIn('iterations', results)
        self.assertIn('encrypt_ops_per_sec', results)
        self.assertIn('decrypt_ops_per_sec', results)
        self.assertIn('encrypt_time_per_op_ms', results)
        self.assertIn('decrypt_time_per_op_ms', results)
        
        # Check reasonable values
        self.assertEqual(results['iterations'], 10)
        self.assertGreater(results['encrypt_ops_per_sec'], 0)
        self.assertGreater(results['decrypt_ops_per_sec'], 0)
        self.assertGreater(results['encrypt_time_per_op_ms'], 0)
        self.assertGreater(results['decrypt_time_per_op_ms'], 0)
    
    def test_bit_rotation(self):
        """Test bit rotation utility function"""
        # Test specific bit rotation cases
        test_cases = [
            (0b10000001, 1, 0b00000011),  # Rotate 129 left by 1 -> 3
            (0b11110000, 4, 0b00001111),  # Rotate 240 left by 4 -> 15
            (0, 3, 0),                    # Rotate 0 -> 0
        ]
        
        for value, rotation, expected in test_cases:
            # Convert to signed byte
            signed_value = value if value < 128 else value - 256
            signed_expected = expected if expected < 128 else expected - 256
            
            result = self.engine._rotate_bits(signed_value, rotation)
            self.assertEqual(result, signed_expected)
    
    def test_tensor_product_operation(self):
        """Test tensor product operations"""
        tensor_a = np.array([[1, 2], [3, 4]], dtype=np.int8)
        tensor_b = np.array([[5, 6], [7, 8]], dtype=np.int8)
        
        result = self.engine._tensor_product_operation(tensor_a, tensor_b)
        
        # Check result properties
        self.assertEqual(result.shape, tensor_a.shape)
        self.assertEqual(result.dtype, np.int8)
        
        # Result should be different from inputs
        self.assertFalse(np.array_equal(result, tensor_a))
        self.assertFalse(np.array_equal(result, tensor_b))
    
    def test_cryptographic_transformations(self):
        """Test cryptographic transformations"""
        original_tensor = np.random.randint(-128, 127, (4, 4), dtype=np.int8)
        
        # Apply transformations
        transformed = self.engine._apply_cryptographic_transformations(original_tensor)
        
        # Check properties
        self.assertEqual(transformed.shape, original_tensor.shape)
        self.assertEqual(transformed.dtype, original_tensor.dtype)
        
        # Should be different from original (unless extremely unlikely)
        self.assertFalse(np.array_equal(transformed, original_tensor))
    
    def test_session_transformations(self):
        """Test session-specific transformations"""
        original_tensor = np.random.randint(-128, 127, (4, 4), dtype=np.int8)
        session_key = b"test_session_key_32_bytes_long12"
        
        # Apply session transformations
        transformed = self.engine._apply_session_transformations(original_tensor, session_key)
        
        # Check properties
        self.assertEqual(transformed.shape, original_tensor.shape)
        self.assertEqual(transformed.dtype, original_tensor.dtype)
        
        # Same key should produce same result (deterministic)
        transformed2 = self.engine._apply_session_transformations(original_tensor, session_key)
        self.assertTrue(np.array_equal(transformed, transformed2))
        
        # Different key should produce different result
        different_key = b"different_key_32_bytes_long123"
        transformed3 = self.engine._apply_session_transformations(original_tensor, different_key)
        self.assertFalse(np.array_equal(transformed, transformed3))
    
    def test_encryption_layer_invertibility(self):
        """Test that encryption layers are properly invertible"""
        data_tensor = np.random.randint(-128, 127, (4, 4), dtype=np.int8)
        key_tensor = np.random.randint(-128, 127, (4, 4), dtype=np.int8)
        
        # Apply encryption layers
        encrypted = self.engine._apply_encryption_layers(data_tensor, key_tensor)
        
        # Apply decryption layers
        decrypted = self.engine._apply_decryption_layers(encrypted, key_tensor)
        
        # Should recover original data
        self.assertTrue(np.array_equal(data_tensor, decrypted))
    
    def test_nonlinear_transformation_invertibility(self):
        """Test nonlinear transformation invertibility"""
        data_tensor = np.random.randint(-128, 127, (4, 4), dtype=np.int8)
        key_tensor = np.random.randint(-128, 127, (4, 4), dtype=np.int8)
        
        # Apply nonlinear transformation
        transformed = self.engine._nonlinear_transformation(data_tensor, key_tensor)
        
        # Apply inverse transformation
        recovered = self.engine._inverse_nonlinear_transformation(transformed, key_tensor)
        
        # Should recover original data (within numerical precision)
        self.assertTrue(np.allclose(data_tensor, recovered, atol=1))
    
    def test_permutation_invertibility(self):
        """Test tensor permutation invertibility"""
        data_tensor = np.random.randint(-128, 127, (4, 4), dtype=np.int8)
        key_tensor = np.random.randint(-128, 127, (4, 4), dtype=np.int8)
        
        # Apply permutation
        permuted = self.engine._tensor_permutation(data_tensor, key_tensor)
        
        # Apply inverse permutation
        recovered = self.engine._inverse_tensor_permutation(permuted, key_tensor)
        
        # Should recover original data exactly
        self.assertTrue(np.array_equal(data_tensor, recovered))
    
    def test_advanced_mixing_invertibility(self):
        """Test advanced tensor mixing invertibility"""
        data_tensor = np.random.randint(-128, 127, (4, 4), dtype=np.int8)
        key_tensor = np.random.randint(-128, 127, (4, 4), dtype=np.int8)
        
        # Apply advanced mixing
        mixed = self.engine._advanced_tensor_mixing(data_tensor, key_tensor)
        
        # Apply inverse mixing
        recovered = self.engine._inverse_advanced_tensor_mixing(mixed, key_tensor)
        
        # Should recover original data exactly
        self.assertTrue(np.array_equal(data_tensor, recovered))
    
    def test_clear_history(self):
        """Test clearing transformation history"""
        session_tensor = self.engine.generate_session_tensor(
            self.session_id, self.device_fingerprint
        )
        
        # Perform some operations
        encrypted_data, metadata = self.engine.encrypt_data(
            self.test_data, session_tensor
        )
        
        # Verify history exists
        self.assertGreater(len(self.engine.transformation_history), 0)
        
        # Clear history
        self.engine.clear_history()
        
        # Verify history is cleared
        self.assertEqual(len(self.engine.transformation_history), 0)
    
    def test_string_representation(self):
        """Test string representation of engine"""
        repr_str = repr(self.engine)
        
        self.assertIn('TensorEncryptionEngine', repr_str)
        self.assertIn('dims=(4, 4)', repr_str)
        self.assertIn("security='standard'", repr_str)
        self.assertIn('operations=', repr_str)


class TestTensorEngineEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions"""
    
    def setUp(self):
        """Set up test environment"""
        self.engine = TensorEncryptionEngine(tensor_dimensions=(2, 2), security_level='basic')
    
    def test_invalid_security_level(self):
        """Test handling of invalid security level"""
        # Should default to 'standard' for invalid level
        engine = TensorEncryptionEngine(security_level='invalid')
        self.assertEqual(engine.security_params['pbkdf2_iterations'], 50000)  # standard level
    
    def test_very_small_tensor(self):
        """Test with very small tensor dimensions"""
        small_engine = TensorEncryptionEngine(tensor_dimensions=(2, 2))
        
        # Should still work with small data
        test_data = b"Hi"
        session_tensor = small_engine.generate_session_tensor("test", "device")
        
        encrypted_data, metadata = small_engine.encrypt_data(test_data, session_tensor)
        decrypted_data = small_engine.decrypt_data(encrypted_data, session_tensor, metadata)
        
        self.assertEqual(decrypted_data, test_data)
    
    def test_large_tensor(self):
        """Test with larger tensor dimensions"""
        large_engine = TensorEncryptionEngine(tensor_dimensions=(16, 16))
        
        # Should work with larger tensor
        test_data = b"This is a longer test message that can fit in the larger tensor space"
        session_tensor = large_engine.generate_session_tensor("test", "device")
        
        encrypted_data, metadata = large_engine.encrypt_data(test_data, session_tensor)
        decrypted_data = large_engine.decrypt_data(encrypted_data, session_tensor, metadata)
        
        self.assertEqual(decrypted_data, test_data)


if __name__ == '__main__':
    # Configure test runner
    unittest.main(verbosity=2, buffer=True)
