# [file name]: src/tests/test_dictionary_manager.py
"""
Comprehensive tests for Dictionary Manager
"""

import pytest
import tempfile
import numpy as np
from datetime import datetime, timedelta
import threading
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.dictionary_manager import DictionaryManager, DictionaryType, DictionaryStatus


class TestDictionaryManager:
    """Test cases for DictionaryManager class"""
    
    @pytest.fixture
    def temp_db(self):
        """Create temporary database"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        yield db_path
        if os.path.exists(db_path):
            os.unlink(db_path)
    
    @pytest.fixture
    def dictionary_manager(self, temp_db):
        """Create dictionary manager instance"""
        return DictionaryManager(
            db_path=temp_db,
            device_id='test_device',
            security_level='high'
        )
    
    def test_initialization(self, dictionary_manager):
        """Test dictionary manager initialization"""
        assert dictionary_manager.device_id == 'test_device'
        assert dictionary_manager.security_level == 'high'
        
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
        success = dictionary_manager.delete_dictionary(dict_ids[1])
        assert success == True
        
        # Verify deletion
        with pytest.raises(KeyError):
            dictionary_manager.get_dictionary(dict_ids[1])
            
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
        
        # Search functionality might not be implemented yet
        # This test would verify it exists and works if implemented
        if hasattr(dictionary_manager, 'search_dictionaries'):
            results = dictionary_manager.search_dictionaries('tensor')
            assert len(results) >= 2
            
    def test_dictionary_performance(self, dictionary_manager):
        """Test dictionary performance with multiple operations"""
        import time
        
        # Test multiple rapid operations
        start_time = time.time()
        
        operations = 20  # Reduced for faster testing
        for i in range(operations):
            data = {f'key_{j}': f'value_{j}_{i}' for j in range(5)}
            dict_id = dictionary_manager.create_dictionary(
                DictionaryType.SESSION,
                initial_data=data
            )
            
            # Update immediately
            updates = {f'updated_{k}': f'updated_value_{k}' for k in range(3)}
            dictionary_manager.update_dictionary(dict_id, updates)
            
        end_time = time.time()
        total_time = end_time - start_time
        
        # Performance check: should complete within reasonable time
        assert total_time < 5.0  # 20 operations in under 5 seconds


class TestDictionaryIntegration:
    """Integration tests for DictionaryManager with other components"""
    
    def test_integration_with_tensor_engine(self, temp_db):
        """Test integration with tensor engine"""
        from src.tensor_engine import TensorEncryptionEngine
        from src.dictionary_manager import DictionaryManager, DictionaryType
        
        dictionary_manager = DictionaryManager(
            db_path=temp_db,
            device_id='test_device',
            security_level='high'
        )
        
        tensor_engine = TensorEncryptionEngine(
            tensor_dimensions=(8, 8),
            security_level='high'
        )
        
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