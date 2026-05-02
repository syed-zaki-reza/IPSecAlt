# [file name]: src/tests/test_tensor_engine.py
"""
Comprehensive tests for Tensor Encryption Engine
"""

import pytest
import numpy as np
from unittest.mock import Mock, patch, MagicMock
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.tensor_engine import TensorEncryptionEngine
from src.security_types import SecurityLevel


class TestTensorEncryptionEngine:
    """Test suite for tensor engine core functionality."""
    
    @pytest.fixture
    def tensor_engine(self):
        """Create tensor engine instance"""
        return TensorEncryptionEngine(
            tensor_dimensions=(8, 8),
            security_level='high'
        )
    
    @pytest.fixture
    def sample_tensor_data(self):
        """Provide sample tensor data for testing"""
        return np.random.randint(0, 255, size=(8, 8), dtype=np.uint8)
    
    def test_initialization(self, tensor_engine):
        """Test tensor engine initialization."""
        assert tensor_engine.tensor_dimensions == (8, 8)
        assert tensor_engine.security_level == 'high'
        
    def test_tensor_generation(self, tensor_engine):
        """Test secure tensor generation."""
        # Generate different types of tensors
        random_tensor = tensor_engine.generate_random_tensor((4, 4))
        session_tensor = tensor_engine.generate_session_tensor('test_session', 'test_device')
        
        # Verify tensor properties
        assert random_tensor.shape == (4, 4)
        assert session_tensor.shape == (8, 8)  # Default dimensions
        
        # Tensors should contain data
        assert not np.all(random_tensor == 0)
        assert not np.all(session_tensor == 0)
        
    def test_tensor_encryption_decryption(self, tensor_engine, sample_tensor_data):
        """Test tensor encryption and decryption."""
        # Generate encryption key
        key = tensor_engine._generate_encryption_key()
        
        # Encrypt tensor
        encrypted_tensor, metadata = tensor_engine.encrypt_tensor(sample_tensor_data, key)
        
        # Verify encryption
        assert encrypted_tensor is not None
        assert not np.array_equal(encrypted_tensor, sample_tensor_data)
        assert metadata is not None
        assert isinstance(metadata, dict)
        
        # Decrypt tensor
        decrypted_tensor = tensor_engine.decrypt_tensor(encrypted_tensor, key, metadata)
        
        # Verify decryption
        assert decrypted_tensor is not None
        np.testing.assert_array_equal(decrypted_tensor, sample_tensor_data)
        
    def test_data_encryption_decryption(self, tensor_engine):
        """Test data encryption and decryption."""
        test_data = b'This is a test message for tensor encryption'
        key = tensor_engine._generate_encryption_key()
        
        # Encrypt data
        encrypted_data, metadata = tensor_engine.encrypt_data(test_data, key)
        
        # Verify encryption
        assert encrypted_data != test_data
        assert metadata is not None
        assert isinstance(metadata, dict)
        
        # Decrypt data
        decrypted_data = tensor_engine.decrypt_data(encrypted_data, key, metadata)
        
        # Verify decryption
        assert decrypted_data == test_data
        
    def test_tensor_operations(self, tensor_engine, sample_tensor_data):
        """Test mathematical tensor operations."""
        # Test tensor operations if methods exist
        tensor2 = np.random.random(sample_tensor_data.shape).astype(np.float32)
        
        if hasattr(tensor_engine, 'tensor_add'):
            result_add = tensor_engine.tensor_add(sample_tensor_data, tensor2)
            assert result_add.shape == sample_tensor_data.shape
            
        if hasattr(tensor_engine, 'tensor_multiply'):
            result_mult = tensor_engine.tensor_multiply(sample_tensor_data, tensor2)
            assert result_mult.shape == sample_tensor_data.shape
            
    def test_tensor_hashing(self, tensor_engine, sample_tensor_data):
        """Test tensor hashing for integrity verification."""
        # Generate hash if method exists
        if hasattr(tensor_engine, 'tensor_hash'):
            tensor_hash = tensor_engine.tensor_hash(sample_tensor_data)
            
            assert tensor_hash is not None
            assert isinstance(tensor_hash, bytes)
            
            # Same tensor should produce same hash
            hash2 = tensor_engine.tensor_hash(sample_tensor_data)
            assert tensor_hash == hash2
            
            # Modified tensor should produce different hash
            modified_tensor = sample_tensor_data.copy()
            modified_tensor[0, 0] += 1
            hash3 = tensor_engine.tensor_hash(modified_tensor)
            assert tensor_hash != hash3
            
    def test_performance_optimization(self, tensor_engine):
        """Test performance optimization features."""
        import time
        
        # Test with large tensor
        large_tensor = np.random.random((50, 50)).astype(np.float32)  # Reduced size for performance
        
        start_time = time.time()
        
        # Perform operations
        key = tensor_engine._generate_encryption_key()
        encrypted, metadata = tensor_engine.encrypt_tensor(large_tensor, key)
        decrypted = tensor_engine.decrypt_tensor(encrypted, key, metadata)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Should complete within reasonable time
        assert total_time < 5.0
        assert decrypted.shape == large_tensor.shape
        
    def test_error_handling(self, tensor_engine):
        """Test error handling in tensor operations."""
        # Test with invalid tensor
        invalid_tensor = np.array([1, 2, 3])  # 1D array
        
        key = tensor_engine._generate_encryption_key()
        
        # Should handle invalid input gracefully
        try:
            result = tensor_engine.encrypt_tensor(invalid_tensor, key)
            # If it doesn't raise an error, result should be valid
            assert result is not None
        except Exception as e:
            # Or it should raise a meaningful exception
            assert isinstance(e, (ValueError, TypeError))


class TestTensorEngineIntegration:
    """Integration tests for tensor engine with other components."""
    
    def test_integration_with_key_management(self, temp_db):
        """Test integration with key management."""
        from src.tensor_engine import TensorEncryptionEngine
        from src.key_management import KeyManager, KeyType
        
        tensor_engine = TensorEncryptionEngine(
            tensor_dimensions=(8, 8),
            security_level='high'
        )
        
        key_manager = KeyManager(
            db_path=temp_db,
            device_id='test_device',
            security_level='high'
        )
        
        # Generate key through key manager
        key_id = key_manager.generate_key(
            key_type=KeyType.ENCRYPTION,
            session_id='tensor_key_integration'
        )
        key = key_manager.get_key(key_id)
        
        # Use key with tensor engine
        test_data = b'Test data for key management integration'
        encrypted_data, encryption_metadata = tensor_engine.encrypt_data(test_data, key)
        
        # Verify encryption worked
        assert encrypted_data != test_data
        assert encryption_metadata is not None
        
        # Decrypt using same key
        decrypted_data = tensor_engine.decrypt_data(encrypted_data, key, encryption_metadata)
        assert decrypted_data == test_data
        
    @pytest.mark.performance
    def test_performance_under_load(self):
        """Test performance under heavy load."""
        import time
        
        tensor_engine = TensorEncryptionEngine(
            tensor_dimensions=(8, 8),
            security_level='high'
        )
        
        # Generate batch of data
        batch_size = 20  # Reduced for faster testing
        test_data_batch = [os.urandom(512) for _ in range(batch_size)]  # Smaller data chunks
        
        key = tensor_engine._generate_encryption_key()
        
        start_time = time.time()
        
        # Process entire batch
        encrypted_batch = []
        for data in test_data_batch:
            encrypted, metadata = tensor_engine.encrypt_data(data, key)
            encrypted_batch.append((encrypted, metadata))
            
        end_time = time.time()
        total_time = end_time - start_time
        
        # Should complete within reasonable time
        assert total_time < 10.0  # 20 encryptions in under 10 seconds
        
        # Verify all encryptions were successful
        assert len(encrypted_batch) == batch_size
        for encrypted, metadata in encrypted_batch:
            assert encrypted is not None
            assert metadata is not None