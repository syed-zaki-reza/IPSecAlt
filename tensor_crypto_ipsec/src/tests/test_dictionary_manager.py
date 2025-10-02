# [file name]: src/tests/test_dictionary_manager.py
"""
Comprehensive tests for Dictionary Manager
"""

import pytest
import tempfile
import numpy as np
from datetime import datetime, timedelta

from src import DictionaryManager, DictionaryType, DictionaryStatus
from .conftest import dictionary_manager, temp_db_path


class TestDictionaryManager:
    """Test cases for DictionaryManager class"""
    
    def test_initialization(self, dictionary_manager):
        """Test dictionary manager initialization"""
        assert dictionary_manager.device_id == 'test_device'
        assert dictionary_manager.security_level == 'high'
        assert dictionary_manager.enable_caching == True
        
    def test_create_dictionary(self, dictionary_manager):
        """Test dictionary creation"""
        # Create dictionary with initial data
        initial_data = {
            'tensor_data': [1, 2, 3, 4],
            'logic_vector': [5, 6, 7, 8],
            'metadata': {'version': '1.0.0'}
        }
        
        dict_id = dictionary_manager.create_dictionary(
            dictionary_type=DictionaryType.TENSOR,
            initial_data=initial_data,
            session_id='test_session',
            tags=['test', 'tensor'],
            expiration_hours=24
        )
        
        assert dict_id is not None
        assert isinstance(dict_id, str)
        assert dict_id.startswith('dict_')
        
    def test_retrieve_dictionary(self, dictionary_manager):
        """Test dictionary retrieval"""
        # Create dictionary
        test_data = {'key1': 'value1', 'key2': 'value2', 'array_data': [1, 2, 3]}
        dict_id = dictionary_manager.create_dictionary(
            DictionaryType.SESSION,
            initial_data=test_data
        )
        
        # Retrieve dictionary
        retrieved_data = dictionary_manager.get_dictionary(dict_id)
        
        assert retrieved_data == test_data
        assert 'key1' in retrieved_data
        assert retrieved_data['key2'] == 'value2'
        
    def test_update_dictionary(self, dictionary_manager):
        """Test dictionary updates"""
        # Create initial dictionary
        initial_data = {'key1': 'value1', 'key2': 'value2'}
        dict_id = dictionary_manager.create_dictionary(
            DictionaryType.LOGIC,
            initial_data=initial_data
        )
        
        # Update dictionary
        updates = {'key2': 'updated_value', 'key3': 'new_value'}
        success = dictionary_manager.update_dictionary(dict_id, updates)
        
        assert success == True
        
        # Verify updates
        updated_data = dictionary_manager.get_dictionary(dict_id)
        assert updated_data['key1'] == 'value1'  # Original value preserved
        assert updated_data['key2'] == 'updated_value'  # Updated value
        assert updated_data['key3'] == 'new_value'  # New value
        
    def test_dictionary_compression(self, dictionary_manager):
        """Test dictionary compression functionality"""
        # Create large dictionary to test compression
        large_data = {f'key_{i}': f'value_{i}' * 100 for i in range(100)}
        
        dict_id = dictionary_manager.create_dictionary(
            DictionaryType.COMBINED,
            initial_data=large_data
        )
        
        # Verify compression ratio is reasonable
        dictionaries = dictionary_manager.list_dictionaries()
        test_dict = next(d for d in dictionaries if d.dictionary_id == dict_id)
        
        assert test_dict.compression_ratio > 1.0  # Should have some compression
        assert test_dict.entropy_score > 0  # Should have positive entropy
        
    def test_dictionary_encryption(self, dictionary_manager):
        """Test dictionary encryption at rest"""
        sensitive_data = {
            'secret_key': 'very_secret_value',
            'api_token': 'token_123456789',
            'config': {'password': 'super_secure'}
        }
        
        dict_id = dictionary_manager.create_dictionary(
            DictionaryType.SESSION,
            initial_data=sensitive_data
        )
        
        # Verify data is encrypted in database
        # This would require accessing internal methods to verify encryption
        retrieved_data = dictionary_manager.get_dictionary(dict_id)
        
        # Data should be decrypted transparently
        assert retrieved_data == sensitive_data
        assert retrieved_data['secret_key'] == 'very_secret_value'
        
    def test_dictionary_integrity(self, dictionary_manager):
        """Test dictionary data integrity verification"""
        test_data = {'important': 'data', 'numbers': [1, 2, 3, 4, 5]}
        
        dict_id = dictionary_manager.create_dictionary(
            DictionaryType.TENSOR,
            initial_data=test_data
        )
        
        # Verify integrity hash is stored
        dictionaries = dictionary_manager.list_dictionaries()
        test_dict = next(d for d in dictionaries if d.dictionary_id == dict_id)
        
        assert test_dict.integrity_hash is not None
        assert len(test_dict.integrity_hash) > 0
        
    def test_dictionary_deletion(self, dictionary_manager):
        """Test dictionary deletion"""
        # Create multiple dictionaries
        dict_ids = []
        for i in range(3):
            dict_id = dictionary_manager.create_dictionary(
                DictionaryType.EPHEMERAL,
                initial_data={f'test_{i}': f'value_{i}'}
            )
            dict_ids.append(dict_id)
        
        # Delete one dictionary
        success = dictionary_manager.delete_dictionary(dict_ids[1], permanent=False)
        assert success == True
        
        # Verify deletion
        dictionaries = dictionary_manager.list_dictionaries()
        active_dicts = [d for d in dictionaries if d.status == DictionaryStatus.ACTIVE]
        assert len(active_dicts) == 2
        
        # Verify the specific dictionary is archived
        archived_dicts = dictionary_manager.list_dictionaries(status=DictionaryStatus.ARCHIVED)
        assert len(archived_dicts) == 1
        assert archived_dicts[0].dictionary_id == dict_ids[1]
        
    def test_dictionary_search(self, dictionary_manager):
        """Test dictionary search functionality"""
        # Create dictionaries with specific content
        test_data_1 = {'name': 'alpha', 'type': 'tensor', 'value': 100}
        test_data_2 = {'name': 'beta', 'type': 'logic', 'value': 200}
        test_data_3 = {'name': 'gamma', 'type': 'tensor', 'value': 300}
        
        dict_1 = dictionary_manager.create_dictionary(
            DictionaryType.TENSOR,
            initial_data=test_data_1,
            tags=['search_test', 'tensor']
        )
        dict_2 = dictionary_manager.create_dictionary(
            DictionaryType.LOGIC, 
            initial_data=test_data_2,
            tags=['search_test', 'logic']
        )
        dict_3 = dictionary_manager.create_dictionary(
            DictionaryType.TENSOR,
            initial_data=test_data_3,
            tags=['search_test', 'tensor']
        )
        
        # Search by content
        results = dictionary_manager.search_dictionaries('tensor', ['value'])
        assert len(results) >= 2  # Should find at least the tensor dictionaries
        
        # Search by key
        results = dictionary_manager.search_dictionaries('name', ['entry_key'])
        assert len(results) >= 3  # Should find all dictionaries
        
    def test_dictionary_export_import(self, dictionary_manager):
        """Test dictionary export and import"""
        original_data = {
            'tensor_config': {'dimensions': (8, 8), 'dtype': 'int8'},
            'logic_chain': ['operation1', 'operation2', 'operation3'],
            'metadata': {'version': '2.0.0', 'created': '2024-01-01'}
        }
        
        # Create and export dictionary
        dict_id = dictionary_manager.create_dictionary(
            DictionaryType.COMBINED,
            initial_data=original_data
        )
        
        export_password = 'test_export_password'
        export_data = dictionary_manager.export_dictionary(dict_id, export_password)
        
        assert export_data is not None
        assert len(export_data) > 0
        
        # Import dictionary
        new_dict_id = dictionary_manager.import_dictionary(
            export_data, 
            export_password, 
            overwrite=True
        )
        
        # Verify imported data matches original
        imported_data = dictionary_manager.get_dictionary(new_dict_id)
        assert imported_data == original_data
        
    def test_dictionary_performance(self, dictionary_manager):
        """Test dictionary performance with multiple operations"""
        import time
        
        # Test multiple rapid operations
        start_time = time.time()
        
        operations = 50
        for i in range(operations):
            data = {f'key_{j}': f'value_{j}_{i}' for j in range(10)}
            dict_id = dictionary_manager.create_dictionary(
                DictionaryType.SESSION,
                initial_data=data
            )
            
            # Update immediately
            updates = {f'updated_{k}': f'updated_value_{k}' for k in range(5)}
            dictionary_manager.update_dictionary(dict_id, updates)
            
            # Retrieve and verify
            retrieved = dictionary_manager.get_dictionary(dict_id)
            assert len(retrieved) == 15  # 10 original + 5 updates
            
        end_time = time.time()
        total_time = end_time - start_time
        
        # Performance check: should complete within reasonable time
        assert total_time < 10.0  # 50 operations in under 10 seconds
        
        # Verify metrics
        metrics = dictionary_manager.get_performance_metrics()
        assert metrics['dictionaries_created'] >= operations
        assert metrics['dictionaries_updated'] >= operations
        
    def test_dictionary_concurrent_access(self, dictionary_manager):
        """Test concurrent dictionary access"""
        import threading
        
        # Create shared dictionary
        shared_dict_id = dictionary_manager.create_dictionary(
            DictionaryType.SESSION,
            initial_data={'counter': 0, 'data': []}
        )
        
        # Thread function
        results = []
        errors = []
        
        def worker_thread(thread_id):
            try:
                # Each thread updates the dictionary
                for i in range(10):
                    updates = {
                        f'thread_{thread_id}_update_{i}': f'value_{i}',
                        'counter': i  # Will be overwritten, but tests concurrency
                    }
                    success = dictionary_manager.update_dictionary(shared_dict_id, updates)
                    if success:
                        results.append((thread_id, i, 'success'))
                    else:
                        results.append((thread_id, i, 'failure'))
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
        
        # Verify no errors and all operations completed
        assert len(errors) == 0, f"Thread errors: {errors}"
        assert len(results) == 50  # 5 threads * 10 operations each
        
        # Verify final dictionary state
        final_data = dictionary_manager.get_dictionary(shared_dict_id)
        assert 'counter' in final_data
        assert len(final_data) > 5  # Should have entries from all threads


class TestDictionaryIntegration:
    """Integration tests for DictionaryManager with other components"""
    
    def test_integration_with_tensor_engine(self, dictionary_manager, tensor_engine):
        """Test integration with tensor engine"""
        # Generate tensor data
        session_tensor = tensor_engine.generate_session_tensor(
            'integration_test', 
            'test_device'
        )
        
        # Store tensor in dictionary
        tensor_data = {
            'tensor_shape': session_tensor.shape,
            'tensor_data': session_tensor.tolist(),
            'tensor_dtype': str(session_tensor.dtype),
            'metadata': {'generated_by': 'tensor_engine'}
        }
        
        dict_id = dictionary_manager.create_dictionary(
            DictionaryType.TENSOR,
            initial_data=tensor_data
        )
        
        # Retrieve and verify
        stored_data = dictionary_manager.get_dictionary(dict_id)
        retrieved_tensor = np.array(stored_data['tensor_data'], dtype=session_tensor.dtype)
        
        assert retrieved_tensor.shape == session_tensor.shape
        assert np.array_equal(retrieved_tensor, session_tensor)
        
    def test_integration_with_ai_logic(self, dictionary_manager, ai_logic_generator):
        """Test integration with AI logic generator"""
        # Generate AI logic
        logic_vector, metadata = ai_logic_generator.generate_session_logic(
            'ai_integration_test',
            'test_device'
        )
        
        # Store logic in dictionary
        logic_data = {
            'logic_vector': logic_vector.tolist(),
            'logic_metadata': {
                'entropy_score': metadata.entropy_score,
                'complexity_score': metadata.complexity_score,
                'generation_time': metadata.generation_time
            }
        }
        
        dict_id = dictionary_manager.create_dictionary(
            DictionaryType.AI_LOGIC,
            initial_data=logic_data
        )
        
        # Retrieve and verify
        stored_data = dictionary_manager.get_dictionary(dict_id)
        retrieved_vector = np.array(stored_data['logic_vector'], dtype=logic_vector.dtype)
        
        assert retrieved_vector.shape == logic_vector.shape
        assert np.array_equal(retrieved_vector, logic_vector)
        assert stored_data['logic_metadata']['entropy_score'] == metadata.entropy_score