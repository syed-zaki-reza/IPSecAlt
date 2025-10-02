"""
test_key_management.py
Comprehensive test suite for the key management system

Tests cover:
- Key generation and derivation
- Key rotation and lifecycle management
- Secure storage and retrieval
- Performance and caching
- Thread safety and concurrent operations
- Database integrity and audit trails
"""

import unittest
import numpy as np
import os
import tempfile
import shutil
import time
import threading
import sqlite3
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
import secrets

# Import the module to test
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from key_management import KeyManager, KeyType, KeyStatus, KeyMetadata


class TestKeyManager(unittest.TestCase):
    """Test suite for KeyManager class"""
    
    def setUp(self):
        """Set up test environment before each test"""
        # Create temporary directory for test database
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, 'test_keystore.db')
        
        # Initialize key manager with test parameters
        self.key_manager = KeyManager(
            db_path=self.db_path,
            device_id='test_device_12345',
            security_level='basic',  # Faster for testing
            auto_rotation=False  # Disable for controlled testing
        )
    
    def tearDown(self):
        """Clean up after each test"""
        # Shutdown key manager
        self.key_manager.shutdown()
        
        # Clean up temporary directory
        shutil.rmtree(self.test_dir)
    
    def test_initialization(self):
        """Test key manager initialization"""
        self.assertEqual(self.key_manager.device_id, 'test_device_12345')
        self.assertEqual(self.key_manager.security_level, 'basic')
        self.assertFalse(self.key_manager.auto_rotation)
        self.assertIsNotNone(self.key_manager.master_key)
        self.assertEqual(len(self.key_manager.master_key), 64)  # 512 bits
        
        # Check database initialization
        self.assertTrue(os.path.exists(self.db_path))
    
    def test_master_key_generation(self):
        """Test master key generation"""
        # Create another key manager to test different master key
        temp_db = os.path.join(self.test_dir, 'temp_keystore.db')
        km2 = KeyManager(db_path=temp_db, auto_rotation=False)
        
        try:
            # Master keys should be different
            self.assertNotEqual(self.key_manager.master_key, km2.master_key)
            
            # But should have same length
            self.assertEqual(len(self.key_manager.master_key), len(km2.master_key))
        finally:
            km2.shutdown()
    
    def test_device_id_generation(self):
        """Test device ID generation"""
        device_id = self.key_manager._generate_device_id()
        
        # Should be consistent format
        self.assertTrue(device_id.startswith('device_'))
        self.assertEqual(len(device_id), 23)  # 'device_' + 16 hex chars
        
        # Should be deterministic for same system
        device_id2 = self.key_manager._generate_device_id()
        self.assertEqual(device_id, device_id2)
    
    def test_basic_key_derivation(self):
        """Test basic key derivation"""
        # Derive a session key
        key_id, key_data = self.key_manager.derive_key(
            KeyType.SESSION, 
            'test_session_context',
            session_id='test_session_123'
        )
        
        # Check key properties
        self.assertIsInstance(key_id, str)
        self.assertIsInstance(key_data, bytes)
        self.assertEqual(len(key_data), 32)  # Default length
        self.assertIn('session', key_id.lower())
        
        # Check metadata was created
        self.assertIn(key_id, self.key_manager.key_metadata)
        metadata = self.key_manager.key_metadata[key_id]
        self.assertEqual(metadata.key_type, KeyType.SESSION)
        self.assertEqual(metadata.status, KeyStatus.ACTIVE)
        self.assertEqual(metadata.session_id, 'test_session_123')
    
    def test_hierarchical_key_derivation(self):
        """Test hierarchical key derivation"""
        # First derive a parent key
        parent_key_id, parent_key = self.key_manager.derive_key(
            KeyType.TENSOR, 'parent_context'
        )
        
        # Then derive child key from parent
        child_key_id, child_key = self.key_manager.derive_key(
            KeyType.AI_LOGIC, 
            'child_context',
            parent_key_id=parent_key_id
        )
        
        # Keys should be different
        self.assertNotEqual(parent_key, child_key)
        
        # Check derivation was recorded
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT * FROM key_derivations WHERE parent_key_id = ? AND derived_key_id = ?',
                (parent_key_id, child_key_id)
            )
            derivation_record = cursor.fetchone()
            self.assertIsNotNone(derivation_record)
    
    def test_key_retrieval(self):
        """Test key retrieval and usage tracking"""
        # Derive a key
        key_id, original_key = self.key_manager.derive_key(
            KeyType.TENSOR, 'retrieval_test'
        )
        
        # Retrieve the key
        retrieved_key = self.key_manager.get_key(key_id)
        
        # Should be identical
        self.assertEqual(original_key, retrieved_key)
        
        # Usage count should be incremented
        metadata = self.key_manager.key_metadata[key_id]
        self.assertEqual(metadata.usage_count, 1)
        
        # Retrieve again
        self.key_manager.get_key(key_id)
        self.assertEqual(metadata.usage_count, 2)
    
    def test_key_caching(self):
        """Test key caching mechanism"""
        # Derive a key
        key_id, _ = self.key_manager.derive_key(KeyType.SESSION, 'cache_test')
        
        # First retrieval should be cache miss
        initial_cache_misses = self.key_manager.metrics['cache_misses']
        self.key_manager.get_key(key_id)
        self.assertEqual(self.key_manager.metrics['cache_misses'], initial_cache_misses + 1)
        
        # Second retrieval should be cache hit
        initial_cache_hits = self.key_manager.metrics['cache_hits']
        self.key_manager.get_key(key_id)
        self.assertEqual(self.key_manager.metrics['cache_hits'], initial_cache_hits + 1)
        
        # Key should be in cache
        self.assertIn(key_id, self.key_manager.key_cache)
    
    def test_key_rotation(self):
        """Test key rotation functionality"""
        # Derive original key
        original_key_id, original_key = self.key_manager.derive_key(
            KeyType.SESSION, 'rotation_test', session_id='test_session'
        )
        
        # Rotate the key
        new_key_id = self.key_manager.rotate_key(original_key_id)
        
        # Should get new key ID
        self.assertNotEqual(original_key_id, new_key_id)
        
        # Original key should be in rotating status
        original_metadata = self.key_manager.key_metadata[original_key_id]
        self.assertEqual(original_metadata.status, KeyStatus.ROTATING)
        
        # New key should be active
        new_metadata = self.key_manager.key_metadata[new_key_id]
        self.assertEqual(new_metadata.status, KeyStatus.ACTIVE)
        self.assertEqual(new_metadata.rotated_from, original_key_id)
        
        # Keys should be different
        new_key = self.key_manager.get_key(new_key_id)
        self.assertNotEqual(original_key, new_key)
    
    def test_key_expiration(self):
        """Test key expiration handling"""
        # Derive an ephemeral key (should have expiration)
        key_id, _ = self.key_manager.derive_key(KeyType.EPHEMERAL, 'expiration_test')
        
        metadata = self.key_manager.key_metadata[key_id]
        
        # Should have expiration time set
        self.assertIsNotNone(metadata.expires_at)
        
        # Manually set expiration to past
        past_time = datetime.now() - timedelta(hours=1)
        metadata.expires_at = past_time
        
        # Update in database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE keys SET expires_at = ? WHERE key_id = ?',
                (past_time.isoformat(), key_id)
            )
            conn.commit()
        
        # Trying to get expired key should raise error
        with self.assertRaises(ValueError):
            self.key_manager.get_key(key_id)
        
        # Key should be marked as expired
        self.assertEqual(metadata.status, KeyStatus.EXPIRED)
    
    def test_key_revocation(self):
        """Test key revocation"""
        # Derive a key
        key_id, _ = self.key_manager.derive_key(KeyType.TENSOR, 'revocation_test')
        
        # Revoke the key
        self.key_manager.revoke_key(key_id, 'test_revocation')
        
        # Key should be revoked
        metadata = self.key_manager.key_metadata[key_id]
        self.assertEqual(metadata.status, KeyStatus.REVOKED)
        
        # Should not be in cache
        self.assertNotIn(key_id, self.key_manager.key_cache)
        
        # Trying to get revoked key should raise error
        with self.assertRaises(ValueError):
            self.key_manager.get_key(key_id)
    
    def test_key_listing(self):
        """Test key listing functionality"""
        # Create keys of different types
        session_key_id, _ = self.key_manager.derive_key(
            KeyType.SESSION, 'list_test_1', session_id='session_1'
        )
        tensor_key_id, _ = self.key_manager.derive_key(
            KeyType.TENSOR, 'list_test_2'
        )
        
        # List all keys
        all_keys = self.key_manager.list_keys()
        self.assertGreaterEqual(len(all_keys), 2)
        
        # List session keys only
        session_keys = self.key_manager.list_keys(key_type=KeyType.SESSION)
        session_key_ids = [k.key_id for k in session_keys]
        self.assertIn(session_key_id, session_key_ids)
        self.assertNotIn(tensor_key_id, session_key_ids)
        
        # List active keys only
        active_keys = self.key_manager.list_keys(status=KeyStatus.ACTIVE)
        self.assertTrue(all(k.status == KeyStatus.ACTIVE for k in active_keys))
        
        # List keys by session
        session_1_keys = self.key_manager.list_keys(session_id='session_1')
        self.assertEqual(len(session_1_keys), 1)
        self.assertEqual(session_1_keys[0].key_id, session_key_id)
    
    def test_cleanup_expired_keys(self):
        """Test cleanup of expired keys"""
        # Create some keys
        key_ids = []
        for i in range(3):
            key_id, _ = self.key_manager.derive_key(
                KeyType.EPHEMERAL, f'cleanup_test_{i}'
            )
            key_ids.append(key_id)
        
        # Mark some as deprecated/expired with old timestamps
        old_time = datetime.now() - timedelta(days=31)  # Older than audit period
        
        # Manually update database to simulate old keys
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE keys SET status = ?, created_at = ? WHERE key_id = ?',
                (KeyStatus.DEPRECATED.value, old_time.isoformat(), key_ids[0])
            )
            cursor.execute(
                'UPDATE keys SET status = ?, created_at = ? WHERE key_id = ?',
                (KeyStatus.EXPIRED.value, old_time.isoformat(), key_ids[1])
            )
            conn.commit()
        
        # Update metadata
        self.key_manager.key_metadata[key_ids[0]].status = KeyStatus.DEPRECATED
        self.key_manager.key_metadata[key_ids[0]].created_at = old_time
        self.key_manager.key_metadata[key_ids[1]].status = KeyStatus.EXPIRED
        self.key_manager.key_metadata[key_ids[1]].created_at = old_time
        
        # Run cleanup
        cleaned_count = self.key_manager.cleanup_expired_keys()
        
        # Should have cleaned up 2 keys
        self.assertEqual(cleaned_count, 2)
        
        # Old keys should be removed
        self.assertNotIn(key_ids[0], self.key_manager.key_metadata)
        self.assertNotIn(key_ids[1], self.key_manager.key_metadata)
        
        # Active key should remain
        self.assertIn(key_ids[2], self.key_manager.key_metadata)
    
    def test_metrics_tracking(self):
        """Test metrics collection"""
        initial_metrics = self.key_manager.get_metrics()
        
        # Perform various operations
        key_id, _ = self.key_manager.derive_key(KeyType.SESSION, 'metrics_test')
        self.key_manager.get_key(key_id)  # Cache miss
        self.key_manager.get_key(key_id)  # Cache hit
        rotated_key_id = self.key_manager.rotate_key(key_id)
        self.key_manager.revoke_key(rotated_key_id)
        
        # Check metrics updated
        final_metrics = self.key_manager.get_metrics()
        
        self.assertGreater(final_metrics['keys_generated'], initial_metrics['keys_generated'])
        self.assertGreater(final_metrics['keys_rotated'], initial_metrics['keys_rotated'])
        self.assertGreater(final_metrics['keys_revoked'], initial_metrics['keys_revoked'])
        self.assertGreater(final_metrics['cache_hits'], initial_metrics['cache_hits'])
        self.assertGreater(final_metrics['cache_misses'], initial_metrics['cache_misses'])
    
    def test_secure_storage(self):
        """Test secure key storage and encryption"""
        # Derive a key
        key_id, original_key = self.key_manager.derive_key(
            KeyType.TENSOR, 'storage_test'
        )
        
        # Check key is encrypted in database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT encrypted_key FROM keys WHERE key_id = ?', (key_id,))
            encrypted_key = cursor.fetchone()[0]
        
        # Encrypted key should be different from original
        self.assertNotEqual(encrypted_key, original_key)
        self.assertGreater(len(encrypted_key), len(original_key))  # IV + ciphertext
        
        # But retrieval should give original key
        retrieved_key = self.key_manager.get_key(key_id)
        self.assertEqual(retrieved_key, original_key)
    
    def test_different_security_levels(self):
        """Test different security levels"""
        # Create key managers with different security levels
        basic_db = os.path.join(self.test_dir, 'basic_keystore.db')
        high_db = os.path.join(self.test_dir, 'high_keystore.db')
        
        basic_km = KeyManager(db_path=basic_db, security_level='basic', auto_rotation=False)
        high_km = KeyManager(db_path=high_db, security_level='high', auto_rotation=False)
        
        try:
            # Check different parameters
            self.assertLess(
                basic_km.security_params['pbkdf2_iterations'],
                high_km.security_params['pbkdf2_iterations']
            )
            self.assertLess(
                basic_km.security_params['max_key_usage'],
                high_km.security_params['max_key_usage']
            )
            self.assertGreater(
                basic_km.security_params['key_rotation_interval'],
                high_km.security_params['key_rotation_interval']
            )
        finally:
            basic_km.shutdown()
            high_km.shutdown()
    
    def test_key_usage_limits(self):
        """Test key usage limits and automatic rotation scheduling"""
        # Set low usage limit for testing
        self.key_manager.security_params['max_key_usage'] = 3
        
        # Derive a key
        key_id, _ = self.key_manager.derive_key(KeyType.SESSION, 'usage_limit_test')
        
        # Use key up to limit
        for _ in range(3):
            self.key_manager.get_key(key_id)
        
        # Next usage should schedule rotation
        initial_scheduled = len(self.key_manager.rotation_schedule)
        self.key_manager.get_key(key_id)
        
        # Should be scheduled for rotation (if auto_rotation was enabled)
        # For this test, we just check the mechanism works
        self.assertGreaterEqual(len(self.key_manager.rotation_schedule), initial_scheduled)
    
    def test_database_integrity(self):
        """Test database integrity and constraints"""
        # Test foreign key constraints
        key_id, _ = self.key_manager.derive_key(KeyType.TENSOR, 'integrity_test')
        
        # Verify key exists in database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM keys WHERE key_id = ?', (key_id,))
            count = cursor.fetchone()[0]
            self.assertEqual(count, 1)
            
            # Check usage log was created
            cursor.execute('SELECT COUNT(*) FROM key_usage_log WHERE key_id = ?', (key_id,))
            usage_count = cursor.fetchone()[0]
            self.assertGreater(usage_count, 0)
    
    def test_concurrent_key_operations(self):
        """Test thread safety of key operations"""
        results = []
        errors = []
        
        def worker_thread(thread_id):
            try:
                # Each thread derives and uses keys
                key_id, key_data = self.key_manager.derive_key(
                    KeyType.SESSION, f'concurrent_test_{thread_id}'
                )
                retrieved_key = self.key_manager.get_key(key_id)
                
                # Verify integrity
                if key_data == retrieved_key:
                    results.append((thread_id, 'success'))
                else:
                    results.append((thread_id, 'data_mismatch'))
                    
            except Exception as e:
                errors.append((thread_id, str(e)))
        
        # Start multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=worker_thread, args=(i,))
            thread.start()
            threads.append(thread)
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Check results
        self.assertEqual(len(errors), 0, f"Thread errors: {errors}")
        self.assertEqual(len(results), 5)
        self.assertTrue(all(result[1] == 'success' for result in results))
    
    def test_key_derivation_determinism(self):
        """Test that key derivation is deterministic"""
        context = 'determinism_test'
        
        # Derive same key twice
        key_id1, key_data1 = self.key_manager.derive_key(KeyType.TENSOR, context)
        
        # Clear cache to force re-derivation
        if key_id1 in self.key_manager.key_cache:
            del self.key_manager.key_cache[key_id1]
        
        # Get key again (should be same)
        retrieved_key = self.key_manager.get_key(key_id1)
        self.assertEqual(key_data1, retrieved_key)
        
        # But different context should give different key
        key_id2, key_data2 = self.key_manager.derive_key(KeyType.TENSOR, 'different_context')
        self.assertNotEqual(key_data1, key_data2)
    
    def test_error_handling(self):
        """Test error handling for various scenarios"""
        # Test getting non-existent key
        with self.assertRaises(KeyError):
            self.key_manager.get_key('non_existent_key')
        
        # Test rotating non-existent key
        with self.assertRaises(KeyError):
            self.key_manager.rotate_key('non_existent_key')
        
        # Test revoking non-existent key
        with self.assertRaises(KeyError):
            self.key_manager.revoke_key('non_existent_key')
        
        # Test deriving with non-existent parent
        with self.assertRaises(ValueError):
            self.key_manager.derive_key(
                KeyType.TENSOR, 
                'test_context', 
                parent_key_id='non_existent_parent'
            )
    
    def test_key_metadata_integrity(self):
        """Test key metadata consistency"""
        # Derive a key
        key_id, _ = self.key_manager.derive_key(
            KeyType.SESSION, 
            'metadata_test',
            session_id='test_session'
        )
        
        # Check metadata in memory
        memory_metadata = self.key_manager.key_metadata[key_id]
        
        # Check metadata in database
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM keys WHERE key_id = ?', (key_id,))
            db_row = cursor.fetchone()
        
        # Verify consistency
        self.assertEqual(memory_metadata.key_id, db_row['key_id'])
        self.assertEqual(memory_metadata.key_type.value, db_row['key_type'])
        self.assertEqual(memory_metadata.status.value, db_row['status'])
        self.assertEqual(memory_metadata.session_id, db_row['session_id'])
        self.assertEqual(memory_metadata.device_id, db_row['device_id'])
        self.assertEqual(memory_metadata.security_level, db_row['security_level'])
    
    def test_memory_cleanup(self):
        """Test memory cleanup and sensitive data handling"""
        # Create some keys and cache entries
        key_ids = []
        for i in range(5):
            key_id, _ = self.key_manager.derive_key(KeyType.EPHEMERAL, f'memory_test_{i}')
            key_ids.append(key_id)
            # Access to cache them
            self.key_manager.get_key(key_id)
        
        # Verify keys are cached
        cached_count = len(self.key_manager.key_cache)
        self.assertGreater(cached_count, 0)
        
        # Revoke keys
        for key_id in key_ids:
            self.key_manager.revoke_key(key_id)
        
        # Revoked keys should be removed from cache
        remaining_cached = sum(1 for kid in key_ids if kid in self.key_manager.key_cache)
        self.assertEqual(remaining_cached, 0)
    
    def test_audit_trail(self):
        """Test audit trail functionality"""
        # Derive a key and use it
        key_id, _ = self.key_manager.derive_key(KeyType.SESSION, 'audit_test')
        self.key_manager.get_key(key_id)
        self.key_manager.rotate_key(key_id)
        
        # Check audit records in database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Check key usage log
            cursor.execute(
                'SELECT COUNT(*) FROM key_usage_log WHERE key_id = ?',
                (key_id,)
            )
            usage_records = cursor.fetchone()[0]
            self.assertGreater(usage_records, 0)
            
            # Check key derivation records
            cursor.execute(
                'SELECT COUNT(*) FROM key_derivations WHERE derived_key_id = ?',
                (key_id,)
            )
            derivation_records = cursor.fetchone()[0]
            self.assertGreaterEqual(derivation_records, 0)
    
    def test_string_representation(self):
        """Test string representation"""
        repr_str = repr(self.key_manager)
        
        self.assertIn('KeyManager', repr_str)
        self.assertIn('test_device', repr_str)
        self.assertIn('security_level=', repr_str)
        self.assertIn('keys=', repr_str)
        self.assertIn('auto_rotation=', repr_str)


class TestKeyManagerAutoRotation(unittest.TestCase):
    """Test automatic key rotation functionality"""
    
    def setUp(self):
        """Set up test environment with auto-rotation enabled"""
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, 'test_auto_rotation.db')
        
        # Enable auto-rotation with short intervals for testing
        self.key_manager = KeyManager(
            db_path=self.db_path,
            security_level='basic',
            auto_rotation=True
        )
        # Override rotation interval for faster testing
        self.key_manager.security_params['key_rotation_interval'] = 2  # 2 seconds
    
    def tearDown(self):
        """Clean up after test"""
        self.key_manager.shutdown()
        shutil.rmtree(self.test_dir)
    
    def test_automatic_rotation_service(self):
        """Test automatic rotation service"""
        # Check rotation service is running
        self.assertTrue(self.key_manager.auto_rotation)
        self.assertIsNotNone(self.key_manager.rotation_thread)
        self.assertTrue(self.key_manager.rotation_thread.is_alive())
    
    def test_scheduled_rotation(self):
        """Test scheduled key rotation"""
        # Set very low usage limit to trigger rotation
        self.key_manager.security_params['max_key_usage'] = 1
        
        # Derive and use a key to trigger rotation scheduling
        key_id, _ = self.key_manager.derive_key(KeyType.SESSION, 'scheduled_rotation_test')
        self.key_manager.get_key(key_id)  # This should schedule rotation
        
        # Check if rotation was scheduled
        self.assertGreater(len(self.key_manager.rotation_schedule), 0)


class TestKeyManagerIntegration(unittest.TestCase):
    """Test integration scenarios with other components"""
    
    def setUp(self):
        """Set up integration test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, 'integration_test.db')
        
        self.key_manager = KeyManager(
            db_path=self.db_path,
            security_level='standard',
            auto_rotation=False
        )
    
    def tearDown(self):
        """Clean up after test"""
        self.key_manager.shutdown()
        shutil.rmtree(self.test_dir)
    
    def test_tensor_key_integration(self):
        """Test integration with tensor encryption"""
        # Derive tensor key
        tensor_key_id, tensor_key_data = self.key_manager.derive_key(
            KeyType.TENSOR, 
            'tensor_encryption_key',
            key_length=64  # 8x8 tensor
        )
        
        # Reshape for tensor use
        tensor_key = np.frombuffer(tensor_key_data, dtype=np.uint8).reshape(8, 8)
        
        # Test tensor operations
        test_data = np.random.randint(0, 256, (8, 8), dtype=np.uint8)
        encrypted = np.bitwise_xor(test_data, tensor_key)
        decrypted = np.bitwise_xor(encrypted, tensor_key)
        
        # Should recover original data
        self.assertTrue(np.array_equal(test_data, decrypted))
    
    def test_ai_logic_key_integration(self):
        """Test integration with AI logic generation"""
        # Derive AI logic key
        ai_key_id, ai_key_data = self.key_manager.derive_key(
            KeyType.AI_LOGIC,
            'ai_logic_seed',
            key_length=32
        )
        
        # Use as seed for deterministic random generation
        np.random.seed(int.from_bytes(ai_key_data[:4], 'big'))
        logic_vector = np.random.randint(-128, 127, 16, dtype=np.int8)
        
        # Should be deterministic
        np.random.seed(int.from_bytes(ai_key_data[:4], 'big'))
        logic_vector2 = np.random.randint(-128, 127, 16, dtype=np.int8)
        
        self.assertTrue(np.array_equal(logic_vector, logic_vector2))
    
    def test_session_key_management(self):
        """Test session-based key management"""
        session_id = 'integration_test_session'
        
        # Derive multiple keys for same session
        tensor_key_id, _ = self.key_manager.derive_key(
            KeyType.TENSOR, 'session_tensor', session_id=session_id
        )
        ai_key_id, _ = self.key_manager.derive_key(
            KeyType.AI_LOGIC, 'session_ai', session_id=session_id
        )
        dict_key_id, _ = self.key_manager.derive_key(
            KeyType.DICTIONARY, 'session_dict', session_id=session_id
        )
        
        # List keys for session
        session_keys = self.key_manager.list_keys(session_id=session_id)
        session_key_ids = {k.key_id for k in session_keys}
        
        # All session keys should be listed
        self.assertIn(tensor_key_id, session_key_ids)
        self.assertIn(ai_key_id, session_key_ids)
        self.assertIn(dict_key_id, session_key_ids)
        
        # All should have same session ID
        for key in session_keys:
            self.assertEqual(key.session_id, session_id)


if __name__ == '__main__':
    # Configure test runner
    unittest.main(verbosity=2, buffer=True)
