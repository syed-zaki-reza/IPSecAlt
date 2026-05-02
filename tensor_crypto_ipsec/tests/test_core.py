"""
Unit Tests for Tensor Cryptography System

Tests for core components:
- Chaos Engine (logistic map, permutation generation)
- Tensor Engine (encryption/decryption roundtrip)
- AI Conductor (session management)
"""

import unittest
import numpy as np
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from chaos_engine import ChaosEngine
from tensor_engine import TensorEngine, BlockMetadata
from ai_conductor import AIConductor, SessionState


class TestChaosEngine(unittest.TestCase):
    """Test chaotic sequence generation"""
    
    def setUp(self):
        self.engine = ChaosEngine(mu=4.0, x0=0.5, iterations=512)
    
    def test_logistic_map_range(self):
        """Test logistic map stays in valid range"""
        x = 0.5
        mu = 4.0
        
        for _ in range(1000):
            x = self.engine.logistic_map(x, mu)
            self.assertTrue(0.0 <= x <= 1.0)
    
    def test_sequence_generation(self):
        """Test chaotic sequence generation"""
        seq = self.engine.generate_sequence()
        
        self.assertEqual(len(seq), 512)
        self.assertTrue(all(0.0 < x < 1.0 for x in seq))
    
    def test_deterministic_generation(self):
        """Test same parameters produce same sequence"""
        seq1 = self.engine.generate_sequence(mu=4.0, x0=0.5, iterations=100)
        seq2 = self.engine.generate_sequence(mu=4.0, x0=0.5, iterations=100)
        
        np.testing.assert_array_equal(seq1, seq2)
    
    def test_permutation_indices(self):
        """Test permutation index generation"""
        indices = self.engine.generate_permutation_indices(size=100)
        
        self.assertEqual(len(indices), 100)
        self.assertEqual(set(indices), set(range(100)))
    
    def test_tensor_generation(self):
        """Test 3D tensor generation"""
        tensor = self.engine.generate_tensor(shape=(8, 8, 8))
        
        self.assertEqual(tensor.shape, (8, 8, 8))
        self.assertTrue(all(0.0 < x < 1.0 for x in tensor.flatten()))
    
    def test_session_params_derivation(self):
        """Test deterministic session parameter derivation"""
        x0_1, mu_1 = self.engine.derive_session_params(
            "session1", "device1"
        )
        
        x0_2, mu_2 = self.engine.derive_session_params(
            "session1", "device1"
        )
        
        # Same inputs should produce same outputs
        self.assertEqual(x0_1, x0_2)
        self.assertEqual(mu_1, mu_2)
        
        # Different inputs should produce different outputs
        x0_3, mu_3 = self.engine.derive_session_params(
            "session2", "device1"
        )
        self.assertNotEqual(x0_1, x0_3)


class TestTensorEngine(unittest.TestCase):
    """Test tensor encryption/decryption"""
    
    def setUp(self):
        self.chaos_engine = ChaosEngine(mu=4.0, x0=0.5)
        self.tensor_engine = TensorEngine(
            chaos_engine=self.chaos_engine,
            strategy='voxel_swap'
        )
        self.session_id = "test_session"
        self.mu = 4.0
        self.x0 = 0.5
    
    def test_block_metadata_serialization(self):
        """Test block metadata serialization/deserialization"""
        meta = BlockMetadata(
            actual_length=400,
            block_index=2,
            total_blocks=5,
            checksum=12345
        )
        
        serialized = meta.to_bytes()
        deserialized = BlockMetadata.from_bytes(serialized)
        
        self.assertEqual(meta.actual_length, deserialized.actual_length)
        self.assertEqual(meta.block_index, deserialized.block_index)
        self.assertEqual(meta.total_blocks, deserialized.total_blocks)
        self.assertEqual(meta.checksum, deserialized.checksum)
    
    def test_encryption_decryption_roundtrip(self):
        """Test encrypt then decrypt returns original data"""
        original_data = b"Hello, World! This is a test message."
        
        result = self.tensor_engine.encrypt(
            original_data, self.mu, self.x0, self.session_id
        )
        
        decrypt_result = self.tensor_engine.decrypt(
            result.ciphertext, self.mu, self.x0, self.session_id
        )
        
        self.assertEqual(original_data, decrypt_result.plaintext)
    
    def test_wrong_key_decryption_fails(self):
        """Test decryption with wrong key produces different output"""
        original_data = b"Secret message"
        
        encrypted = self.tensor_engine.encrypt(
            original_data, self.mu, self.x0, self.session_id
        )
        
        # Decrypt with wrong key
        wrong_decrypt = self.tensor_engine.decrypt(
            encrypted.ciphertext, self.mu, 0.6, self.session_id
        )
        
        self.assertNotEqual(original_data, wrong_decrypt.plaintext)
    
    def test_different_messages_produce_different_ciphertext(self):
        """Test different messages produce different ciphertexts"""
        msg1 = b"Message one"
        msg2 = b"Message two"
        
        enc1 = self.tensor_engine.encrypt(msg1, self.mu, self.x0, self.session_id)
        enc2 = self.tensor_engine.encrypt(msg2, self.mu, self.x0, self.session_id)
        
        self.assertNotEqual(enc1.ciphertext, enc2.ciphertext)
    
    def test_large_message_chunking(self):
        """Test large messages are properly chunked"""
        large_data = os.urandom(2000)  # Larger than single block
        
        encrypted = self.tensor_engine.encrypt(
            large_data, self.mu, self.x0, self.session_id
        )
        
        decrypted = self.tensor_engine.decrypt(
            encrypted.ciphertext, self.mu, self.x0, self.session_id
        )
        
        self.assertEqual(large_data, decrypted.plaintext)
        self.assertGreater(encrypted.block_count, 1)
    
    def test_entropy_score(self):
        """Test entropy score calculation"""
        data = b"Test data for entropy"
        
        result = self.tensor_engine.encrypt(
            data, self.mu, self.x0, self.session_id
        )
        
        # Entropy should be reasonable (> 3.0 bits)
        self.assertGreater(result.entropy_score, 3.0)


class TestAIConductor(unittest.TestCase):
    """Test AI conductor session management"""
    
    def setUp(self):
        self.conductor = AIConductor()
    
    def test_session_initiation(self):
        """Test session creation"""
        session = self.conductor.initiate_session(
            session_id="test1",
            device_fingerprint="device_A",
            peer_fingerprint="device_B"
        )
        
        self.assertEqual(session.state, SessionState.ACTIVE)
        self.assertIsNotNone(session.x0)
        self.assertIsNotNone(session.mu)
        self.assertIn(session.strategy, AIConductor.AVAILABLE_STRATEGIES)
    
    def test_session_retrieval(self):
        """Test retrieving active session"""
        self.conductor.initiate_session(
            session_id="test2",
            device_fingerprint="dev1",
            peer_fingerprint="dev2"
        )
        
        session = self.conductor.get_session("test2")
        self.assertIsNotNone(session)
        self.assertEqual(session.state, SessionState.ACTIVE)
    
    def test_session_expiry(self):
        """Test session expiry detection"""
        session = self.conductor.initiate_session(
            session_id="test3",
            device_fingerprint="dev1",
            peer_fingerprint="dev2"
        )
        
        # Manually expire session for testing
        session.expires_at = 0  # Set to past
        
        retrieved = self.conductor.get_session("test3")
        self.assertIsNone(retrieved)
    
    def test_strategy_selection_determinism(self):
        """Test strategy selection is deterministic"""
        seed = 12345
        
        strategy1 = self.conductor.select_strategy(seed)
        strategy2 = self.conductor.select_strategy(seed)
        
        self.assertEqual(strategy1, strategy2)
    
    def test_session_cleanup(self):
        """Test expired session cleanup"""
        # Create sessions
        self.conductor.initiate_session("s1", "d1", "d2")
        self.conductor.initiate_session("s2", "d1", "d2")
        
        # Expire them
        for sid in ["s1", "s2"]:
            self.conductor.sessions[sid].expires_at = 0
        
        cleaned = self.conductor.cleanup_expired_sessions()
        self.assertEqual(cleaned, 2)
        self.assertEqual(self.conductor.get_active_session_count(), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
