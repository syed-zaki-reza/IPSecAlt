# [file name]: src/tests/__init__.py
"""
Test suite for Tensor Crypto IPSec - Quantum-Resistant Encryption System
"""

import os
import sys
import tempfile
import pytest

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Test configuration
TEST_CONFIG = {
    'security_level': 'high',
    'test_timeout': 30,
    'enable_long_tests': False,
    'test_data_dir': tempfile.mkdtemp(prefix='tensor_crypto_test_')
}

# Test utilities
class TestUtils:
    """Utility functions for tests"""
    
    @staticmethod
    def create_test_tensor(shape=(4, 4), dtype=np.int8):
        """Create test tensor with random data"""
        return np.random.randint(-128, 127, size=shape, dtype=dtype)
    
    @staticmethod
    def generate_test_data(size=1024):
        """Generate random test data"""
        return os.urandom(size)
    
    @staticmethod
    def assert_tensor_properties(tensor, expected_shape, expected_dtype):
        """Assert tensor has expected properties"""
        assert tensor.shape == expected_shape, f"Expected shape {expected_shape}, got {tensor.shape}"
        assert tensor.dtype == expected_dtype, f"Expected dtype {expected_dtype}, got {tensor.dtype}"
        assert not np.all(tensor == 0), "Tensor should not contain all zeros"

# Import all test modules
from .test_ai_logic import TestAILogicGenerator, TestAILogicIntegration
from .test_key_management import TestKeyManager, TestKeyManagerIntegration
from .test_tensor_engine import TestTensorEncryptionEngine, TestTensorEngineEdgeCases
from .test_dictionary_manager import TestDictionaryManager, TestDictionaryIntegration
from .test_router_interface import TestRouterInterface, TestRouterIntegration
from .test_utils import TestCryptoUtils, TestPerformanceMonitor, TestSecurityAuditor

__all__ = [
    'TestUtils', 'TEST_CONFIG',
    'TestAILogicGenerator', 'TestAILogicIntegration',
    'TestKeyManager', 'TestKeyManagerIntegration', 
    'TestTensorEncryptionEngine', 'TestTensorEngineEdgeCases',
    'TestDictionaryManager', 'TestDictionaryIntegration',
    'TestRouterInterface', 'TestRouterIntegration',
    'TestCryptoUtils', 'TestPerformanceMonitor', 'TestSecurityAuditor'
]