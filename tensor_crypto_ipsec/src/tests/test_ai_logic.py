# [file name]: src/tests/test_ai_logic.py
"""
Comprehensive tests for AI Logic Generator
"""

import pytest
import numpy as np
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.ai_logic import AILogicGenerator
from src.security_types import SecurityLevel


class TestAILogicGenerator:
    """Test cases for AILogicGenerator class"""
    
    def test_initialization(self):
        """Test AI logic generator initialization"""
        ai_gen = AILogicGenerator(
            input_dim=128,
            output_dim=64,
            architecture='enhanced',
            security_level='quantum',
            training_mode=True
        )
        
        assert ai_gen.input_dim == 128
        assert ai_gen.output_dim == 64
        assert ai_gen.architecture == 'enhanced'
        assert ai_gen.security_level == 'quantum'
        assert ai_gen.training_mode == True
        
    def test_session_logic_generation(self):
        """Test session logic generation"""
        ai_gen = AILogicGenerator(
            input_dim=64,
            output_dim=64,
            architecture='standard',
            security_level='high'
        )
        
        session_id = 'test_session_123'
        device_fingerprint = 'test_device_abc'
        
        # Generate session logic
        logic_vector, metadata = ai_gen.generate_session_logic(
            session_id, device_fingerprint
        )
        
        # Verify results
        assert logic_vector is not None
        assert isinstance(logic_vector, np.ndarray)
        assert logic_vector.shape[0] == ai_gen.output_dim
        assert metadata is not None
        assert isinstance(metadata, dict)
        
        # Verify metadata properties
        assert 'entropy_score' in metadata
        assert 'complexity_score' in metadata
        assert 'generation_time' in metadata
        assert metadata['entropy_score'] > 0
        
    def test_adaptive_learning(self):
        """Test adaptive learning mechanism"""
        ai_gen = AILogicGenerator(
            input_dim=64,
            output_dim=64,
            architecture='standard',
            security_level='high'
        )
        
        # Initial generation
        session_id = 'adaptive_test'
        device_fingerprint = 'test_device'
        
        logic1, meta1 = ai_gen.generate_session_logic(
            session_id, device_fingerprint
        )
        
        # Generate again with same parameters (should be different due to randomness)
        logic2, meta2 = ai_gen.generate_session_logic(
            session_id, device_fingerprint
        )
        
        # Should generate different logic vectors
        assert not np.array_equal(logic1, logic2)
        
    def test_error_handling(self):
        """Test error handling in AI logic generation"""
        ai_gen = AILogicGenerator(
            input_dim=64,
            output_dim=64,
            architecture='standard',
            security_level='high'
        )
        
        # Test with invalid session ID
        with pytest.raises(ValueError):
            ai_gen.generate_session_logic('', 'test_device')
            
        # Test with invalid device fingerprint
        with pytest.raises(ValueError):
            ai_gen.generate_session_logic('test_session', '')
            
    def test_performance_benchmark(self):
        """Test performance benchmarking"""
        import time
        
        ai_gen = AILogicGenerator(
            input_dim=64,
            output_dim=64,
            architecture='standard',
            security_level='high'
        )
        
        start_time = time.time()
        
        # Generate multiple logic vectors
        for i in range(10):
            session_id = f'perf_test_{i}'
            device_fingerprint = f'device_{i}'
            ai_gen.generate_session_logic(session_id, device_fingerprint)
            
        end_time = time.time()
        total_time = end_time - start_time
        
        # Should complete within reasonable time
        assert total_time < 5.0  # 10 generations in under 5 seconds


class TestAILogicIntegration:
    """Integration tests for AILogicGenerator with other components"""
    
    def test_integration_with_tensor_engine(self):
        """Test integration with tensor engine"""
        from src.tensor_engine import TensorEncryptionEngine
        
        ai_gen = AILogicGenerator(
            input_dim=64,
            output_dim=64,
            architecture='standard',
            security_level='high'
        )
        
        tensor_engine = TensorEncryptionEngine(
            tensor_dimensions=(8, 8),
            security_level='high'
        )
        
        # Generate AI logic
        session_id = 'tensor_integration_test'
        device_fingerprint = 'test_device'
        
        logic_vector, metadata = ai_gen.generate_session_logic(
            session_id, device_fingerprint
        )
        
        # Use logic vector with tensor engine
        test_data = np.random.random((8, 8)).astype(np.float32)
        
        # Apply AI logic to tensor data (if method exists)
        if hasattr(tensor_engine, 'apply_ai_logic'):
            transformed_tensor = tensor_engine.apply_ai_logic(test_data, logic_vector)
            assert transformed_tensor is not None
            assert transformed_tensor.shape == test_data.shape
        
    def test_integration_with_key_management(self, temp_db_path):
        """Test integration with key management"""
        from src.key_management import KeyManager
        
        ai_gen = AILogicGenerator(
            input_dim=64,
            output_dim=64,
            architecture='standard',
            security_level='high'
        )
        
        key_manager = KeyManager(
            db_path=temp_db_path,
            device_id='test_device',
            security_level='high'
        )
        
        session_id = 'key_integration_test'
        device_fingerprint = 'test_device'
        
        # Generate AI logic
        logic_vector, metadata = ai_gen.generate_session_logic(
            session_id, device_fingerprint
        )
        
        # Store logic metadata in key manager
        key_id = key_manager.generate_key(
            key_type='session',
            session_id=session_id
        )
        
        # Verify key was created
        assert key_id is not None
        key_info = key_manager.get_key_info(key_id)
        assert key_info is not None