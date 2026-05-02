# [file name]: src/tests/test_key_management.py
"""
Comprehensive tests for Key Management System
"""

import pytest
import numpy as np
import os
import tempfile
from unittest.mock import Mock, patch, MagicMock
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.key_management import KeyManager
from src.security_types import SecurityLevel, KeyType


class TestKeyManager:
    """Test suite for key management functionality."""
    
    @pytest.fixture
    def temp_db(self):
        """Create temporary database"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        yield db_path
        if os.path.exists(db_path):
            os.unlink(db_path)
    
    @pytest.fixture
    def key_manager(self, temp_db):
        """Create key manager instance"""
        return KeyManager(
            db_path=temp_db,
            device_id='test_device',
            security_level='high',
            auto_rotation=False
        )
    
    def test_initialization(self, key_manager):
        """Test key manager initialization."""
        assert key_manager.device_id == 'test_device'
        assert key_manager.security_level == 'high'
        assert key_manager.auto_rotation == False
        
    def test_key_generation(self, key_manager):
        """Test cryptographic key generation."""
        key_id = key_manager.generate_key(
            key_type=KeyType.SESSION,
            session_id='test_session_1'
        )
        
        # Key should be generated and stored
        assert key_id is not None
        assert isinstance(key_id, str)
        
        # Retrieve key info
        key_info = key_manager.get_key_info(key_id)
        assert key_info is not None
        assert key_info.key_id == key_id
        assert key_info.key_type == KeyType.SESSION
        assert key_info.session_id == 'test_session_1'
        
    def test_key_retrieval(self, key_manager):
        """Test key retrieval functionality."""
        key_id = key_manager.generate_key(
            key_type=KeyType.ENCRYPTION,
            session_id='retrieval_test'
        )
        
        # Retrieve the actual key bytes
        key = key_manager.get_key(key_id)
        assert key is not None
        assert isinstance(key, bytes)
        assert len(key) in [16, 24, 32, 64]  # Valid key lengths
        
    def test_nonexistent_key(self, key_manager):
        """Test handling of nonexistent keys."""
        retrieved_key = key_manager.get_key("nonexistent_key")
        assert retrieved_key is None
        
        key_info = key_manager.get_key_info("nonexistent_key")
        assert key_info is None
        
    def test_key_deletion(self, key_manager):
        """Test key deletion functionality."""
        key_id = key_manager.generate_key(
            key_type=KeyType.TEMPORARY,
            session_id='temp_session'
        )
        
        # Verify key exists
        assert key_manager.get_key(key_id) is not None
        
        # Delete key
        success = key_manager.delete_key(key_id)
        assert success == True
        
        # Verify key is gone
        assert key_manager.get_key(key_id) is None
        assert key_manager.get_key_info(key_id) is None
        
    def test_key_rotation(self, key_manager):
        """Test key rotation mechanism."""
        key_id = key_manager.generate_key(
            key_type=KeyType.SESSION,
            session_id='rotation_test'
        )
        
        old_key = key_manager.get_key(key_id)
        old_info = key_manager.get_key_info(key_id)
        
        # Rotate key
        new_key_id = key_manager.rotate_key(key_id)
        
        # Should return same key ID for session keys
        assert new_key_id == key_id
        
        # Verify key changed
        new_key = key_manager.get_key(key_id)
        assert new_key != old_key
        
        # Verify metadata updated
        new_info = key_manager.get_key_info(key_id)
        assert new_info.generation > old_info.generation
        
    def test_key_metadata(self, key_manager):
        """Test key metadata storage and retrieval."""
        metadata = {
            "purpose": "test_encryption",
            "algorithm": "AES-256-GCM",
            "created_by": "test_suite"
        }
        
        key_id = key_manager.generate_key(
            key_type=KeyType.ENCRYPTION,
            session_id='metadata_test',
            metadata=metadata
        )
        
        # Retrieve metadata
        key_info = key_manager.get_key_info(key_id)
        assert key_info.metadata == metadata
        assert key_info.created_at is not None
        
    def test_key_expiration(self, key_manager):
        """Test key expiration functionality."""
        # Create key with short expiration
        key_id = key_manager.generate_key(
            key_type=KeyType.EPHEMERAL,
            session_id='expiration_test',
            expiration_minutes=1  # 1 minute expiration
        )
        
        # Key should be valid initially
        assert key_manager.is_key_valid(key_id) == True
        
    def test_bulk_key_operations(self, key_manager):
        """Test performance with multiple keys."""
        import time
        
        start_time = time.time()
        
        # Create multiple keys
        key_count = 10  # Reduced for faster testing
        key_ids = []
        
        for i in range(key_count):
            key_id = key_manager.generate_key(
                key_type=KeyType.SESSION,
                session_id=f'bulk_test_{i}'
            )
            key_ids.append(key_id)
            
        # Verify all keys are accessible
        for key_id in key_ids:
            key = key_manager.get_key(key_id)
            assert key is not None
            assert len(key) >= 16
            
        end_time = time.time()
        total_time = end_time - start_time
        
        # Should complete within reasonable time
        assert total_time < 5.0
        
        # Cleanup
        for key_id in key_ids:
            key_manager.delete_key(key_id)


class TestKeyManagementIntegration:
    """Integration tests for key management with other components."""
    
    def test_integration_with_tensor_engine(self, temp_db):
        """Test integration with tensor engine."""
        from src.key_management import KeyManager, KeyType
        from src.tensor_engine import TensorEncryptionEngine
        
        key_manager = KeyManager(
            db_path=temp_db,
            device_id='test_device',
            security_level='high'
        )
        
        tensor_engine = TensorEncryptionEngine(
            tensor_dimensions=(8, 8),
            security_level='high'
        )
        
        # Generate session key
        key_id = key_manager.generate_key(
            key_type=KeyType.SESSION,
            session_id='tensor_integration'
        )
        session_key = key_manager.get_key(key_id)
        
        # Encrypt data using tensor engine
        plaintext = b'Test data for tensor engine integration'
        encrypted_data, metadata = tensor_engine.encrypt_data(plaintext, session_key)
        
        # Verify encryption worked
        assert encrypted_data != plaintext
        assert metadata is not None
        
        # Decrypt data
        decrypted_data = tensor_engine.decrypt_data(encrypted_data, session_key, metadata)
        assert decrypted_data == plaintext
        
    def test_secure_session_management(self, temp_db):
        """Test secure session management with key rotation."""
        from src.key_management import KeyManager, KeyType
        
        key_manager = KeyManager(
            db_path=temp_db,
            device_id='test_device',
            security_level='high'
        )
        
        session_id = "secure_game_session"
        
        # Initialize session with initial key
        key_id = key_manager.generate_key(
            key_type=KeyType.SESSION,
            session_id=session_id
        )
        
        # Simulate session progression with periodic key rotation
        for round_num in range(3):
            current_key = key_manager.get_key(key_id)
            current_info = key_manager.get_key_info(key_id)
            
            # Use key for operations
            assert current_key is not None
            
            # Rotate key every round
            if round_num > 0:
                new_key_id = key_manager.rotate_key(key_id)
                new_key = key_manager.get_key(new_key_id)
                assert new_key != current_key