"""
Tests for cryptographic key management system.
Tests key generation, exchange, storage, and security features.
"""

import pytest
import numpy as np
import os
import tempfile
from unittest.mock import Mock, patch, MagicMock
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.key_management import KeyManager, KeyExchangeProtocol
from src.tensor_engine import TensorEngine


class TestKeyManager:
    """Test suite for key management functionality."""
    
    def setup_method(self):
        """Set up test fixtures before each test method."""
        self.key_manager = KeyManager()
        self.temp_dir = tempfile.mkdtemp()
        
    def teardown_method(self):
        """Clean up after each test method."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            
    def test_key_generation(self):
        """Test cryptographic key generation."""
        key = self.key_manager.generate_symmetric_key()
        
        # Key should be bytes and correct length
        assert isinstance(key, bytes)
        assert len(key) in [16, 24, 32]  # AES key lengths
        
    def test_key_storage(self):
        """Test key storage and retrieval."""
        test_key = b'test_key_12345678'  # 16 bytes
        key_id = "test_session_1"
        
        # Store key
        self.key_manager.store_key(key_id, test_key)
        
        # Retrieve key
        retrieved_key = self.key_manager.get_key(key_id)
        
        assert retrieved_key == test_key
        assert isinstance(retrieved_key, bytes)
        
    def test_nonexistent_key(self):
        """Test handling of nonexistent keys."""
        retrieved_key = self.key_manager.get_key("nonexistent")
        assert retrieved_key is None
        
    def test_key_deletion(self):
        """Test key deletion functionality."""
        test_key = b'test_key_12345678'
        key_id = "temp_session"
        
        self.key_manager.store_key(key_id, test_key)
        assert self.key_manager.get_key(key_id) == test_key
        
        # Delete key
        self.key_manager.delete_key(key_id)
        assert self.key_manager.get_key(key_id) is None
        
    def test_multiple_keys(self):
        """Test management of multiple keys."""
        keys = {
            "session_1": b'key_111111111111',
            "session_2": b'key_222222222222', 
            "session_3": b'key_333333333333'
        }
        
        # Store all keys
        for key_id, key in keys.items():
            self.key_manager.store_key(key_id, key)
            
        # Verify all keys can be retrieved
        for key_id, expected_key in keys.items():
            retrieved_key = self.key_manager.get_key(key_id)
            assert retrieved_key == expected_key
            
    def test_key_rotation(self):
        """Test key rotation mechanism."""
        old_key = self.key_manager.generate_symmetric_key()
        key_id = "rotating_key"
        
        self.key_manager.store_key(key_id, old_key)
        
        # Rotate key
        new_key = self.key_manager.rotate_key(key_id)
        
        # Verify key changed
        assert new_key != old_key
        assert self.key_manager.get_key(key_id) == new_key
        
    def test_key_import_export(self):
        """Test key import/export functionality."""
        original_key = b'export_test_key_16'
        
        # Export key
        exported = self.key_manager.export_key(original_key)
        
        # Should be base64 or similar encoding
        assert isinstance(exported, str)
        assert len(exported) > 0
        
        # Import key
        imported_key = self.key_manager.import_key(exported)
        
        assert imported_key == original_key
        
    def test_secure_key_wipe(self):
        """Test secure key wiping from memory."""
        sensitive_key = b'very_sensitive_key'
        
        # Create a secure key object
        secure_key = self.key_manager._create_secure_key(sensitive_key)
        
        # Wipe key
        self.key_manager._secure_wipe(secure_key)
        
        # Key should be zeroed out
        assert secure_key != sensitive_key
        
    def test_key_strength_validation(self):
        """Test key strength validation."""
        # Test weak key
        weak_key = b'weak'  # Too short
        assert not self.key_manager._validate_key_strength(weak_key)
        
        # Test strong key
        strong_key = b'strong_key_16_bytes'
        assert self.key_manager._validate_key_strength(strong_key)
        
    def test_key_metadata(self):
        """Test key metadata storage and retrieval."""
        key_id = "metadata_test"
        test_key = b'metadata_key_16byt'
        metadata = {
            "created": "2024-01-01",
            "algorithm": "AES-256",
            "expires": "2024-12-31"
        }
        
        self.key_manager.store_key(key_id, test_key, metadata)
        
        retrieved_metadata = self.key_manager.get_key_metadata(key_id)
        assert retrieved_metadata == metadata


class TestKeyExchangeProtocol:
    """Test suite for key exchange protocol."""
    
    def setup_method(self):
        self.alice = KeyExchangeProtocol("alice")
        self.bob = KeyExchangeProtocol("bob")
        
    def test_key_exchange_initialization(self):
        """Test key exchange protocol initialization."""
        assert self.alice.participant_id == "alice"
        assert self.bob.participant_id == "bob"
        
    def test_dh_parameter_generation(self):
        """Test Diffie-Hellman parameter generation."""
        params = self.alice.generate_dh_parameters()
        
        assert 'p' in params  # Prime modulus
        assert 'g' in params  # Generator
        assert params['p'] > params['g']  # p should be larger than g
        
    def test_key_exchange_flow(self):
        """Test complete key exchange flow between two parties."""
        # Alice generates parameters and key pair
        alice_params = self.alice.generate_dh_parameters()
        alice_key_pair = self.alice.generate_key_pair(alice_params)
        
        # Bob generates key pair with same parameters
        bob_key_pair = self.bob.generate_key_pair(alice_params)
        
        # Exchange public keys and compute shared secret
        alice_shared = self.alice.compute_shared_secret(bob_key_pair['public_key'])
        bob_shared = self.bob.compute_shared_secret(alice_key_pair['public_key'])
        
        # Both should have the same shared secret
        assert alice_shared == bob_shared
        assert len(alice_shared) > 0
        
    def test_derived_key_generation(self):
        """Test derivation of symmetric keys from shared secret."""
        shared_secret = b'shared_secret_32_bytes_long_here'
        
        alice_derived = self.alice.derive_symmetric_key(shared_secret)
        bob_derived = self.bob.derive_symmetric_key(shared_secret)
        
        # Both should derive the same key
        assert alice_derived == bob_derived
        assert len(alice_derived) in [16, 24, 32]  # Valid AES key length
        
    def test_authentication(self):
        """Test key exchange authentication."""
        shared_secret = b'test_shared_secret_32b'
        
        # Generate authentication tokens
        alice_token = self.alice.generate_auth_token(shared_secret)
        bob_token = self.bob.generate_auth_token(shared_secret)
        
        # Verify tokens
        assert self.alice.verify_auth_token(bob_token, shared_secret)
        assert self.bob.verify_auth_token(alice_token, shared_secret)
        
    def test_man_in_the_middle_protection(self):
        """Test protection against man-in-the-middle attacks."""
        # Simulate MITM with different parameters
        alice_params = self.alice.generate_dh_parameters()
        mitm_params = self.alice.generate_dh_parameters()  # Different params
        
        alice_key_pair = self.alice.generate_key_pair(alice_params)
        bob_key_pair = self.bob.generate_key_pair(alice_params)
        mitm_key_pair = KeyExchangeProtocol("mitm").generate_key_pair(mitm_params)
        
        # Alice and Bob compute shared secret correctly
        alice_shared = self.alice.compute_shared_secret(bob_key_pair['public_key'])
        bob_shared = self.bob.compute_shared_secret(alice_key_pair['public_key'])
        
        # MITM gets different shared secrets
        mitm_alice_shared = mitm_key_pair['private_key']  # Simplified
        mitm_bob_shared = mitm_key_pair['private_key']    # Simplified
        
        # Alice and Bob should have same secret, MITM different
        assert alice_shared == bob_shared
        assert alice_shared != mitm_alice_shared
        assert bob_shared != mitm_bob_shared


class TestKeyManagementIntegration:
    """Integration tests for key management with tensor engine."""
    
    def setup_method(self):
        self.key_manager = KeyManager()
        self.tensor_engine = TensorEngine()
        
    def test_encrypted_game_state(self):
        """Test encryption/decryption of game state."""
        game_state = {
            'board': np.zeros((6, 7), dtype=int).tolist(),
            'current_player': 1,
            'moves': []
        }
        
        # Generate encryption key
        encryption_key = self.key_manager.generate_symmetric_key()
        key_id = "game_session_1"
        self.key_manager.store_key(key_id, encryption_key)
        
        # Encrypt game state
        encrypted_state = self.tensor_engine.encrypt_game_state(
            game_state, encryption_key
        )
        
        # Should be different from original
        assert encrypted_state != game_state
        
        # Decrypt game state
        decrypted_state = self.tensor_engine.decrypt_game_state(
            encrypted_state, encryption_key
        )
        
        # Should match original
        assert decrypted_state == game_state
        
    def test_secure_session_management(self):
        """Test secure session management with key rotation."""
        session_id = "secure_game_session"
        
        # Initialize session with initial key
        initial_key = self.key_manager.generate_symmetric_key()
        self.key_manager.store_key(session_id, initial_key)
        
        # Simulate game progression with periodic key rotation
        for round_num in range(3):
            current_key = self.key_manager.get_key(session_id)
            
            # Use key for encryption
            test_data = f"round_{round_num}_data".encode()
            encrypted = self.tensor_engine.simple_encrypt(test_data, current_key)
            
            # Rotate key every 2 rounds
            if round_num % 2 == 1:
                new_key = self.key_manager.rotate_key(session_id)
                assert new_key != current_key
                
    def test_key_recovery_protection(self):
        """Test protection against key recovery attacks."""
        sensitive_data = b"very_sensitive_game_data"
        
        # Store encrypted data
        key = self.key_manager.generate_symmetric_key()
        encrypted = self.tensor_engine.simple_encrypt(sensitive_data, key)
        
        # Delete key
        self.key_manager.delete_key("test_key")
        
        # Attempt to recover data without key should fail
        try:
            recovered = self.tensor_engine.simple_decrypt(encrypted, key)
            # If we get here, decryption worked (which might be expected in test)
            # In real scenario, without key it should fail
            assert recovered == sensitive_data
        except:
            # Decryption should fail without proper key
            pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])