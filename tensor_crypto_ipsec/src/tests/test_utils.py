# [file name]: src/tests/test_utils.py
"""
Comprehensive tests for Utility Classes
"""

import pytest
import tempfile
import numpy as np
from datetime import datetime, timedelta
import time
import os
import sys

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.utils import (
    CryptoUtils, PerformanceMonitor, DataUtils, SecurityAuditor, ErrorHandler
)
from src.security_types import SecurityLevel


class TestCryptoUtils:
    """Test cases for CryptoUtils class"""
    
    @pytest.fixture
    def crypto_utils(self):
        """Create CryptoUtils instance"""
        return CryptoUtils(security_level=SecurityLevel.HIGH)
    
    def test_initialization(self, crypto_utils):
        """Test CryptoUtils initialization"""
        assert crypto_utils.security_level == SecurityLevel.HIGH
        
    def test_secure_random_generation(self, crypto_utils):
        """Test secure random number generation"""
        # Test different lengths
        for length in [16, 32, 64]:
            random_data = crypto_utils.generate_secure_random(length)
            assert len(random_data) == length
            assert isinstance(random_data, bytes)
            
            # Verify randomness (basic check)
            assert random_data != b'\x00' * length
            
    def test_password_key_derivation(self, crypto_utils):
        """Test password-based key derivation"""
        password = "test_password_123"
        salt = crypto_utils.generate_secure_random(16)
        
        # Derive key with specific salt
        key = crypto_utils.derive_key_from_password(password, salt)
        
        assert key is not None
        assert len(key) in [16, 24, 32]  # Valid key length
        
        # Same password and salt should produce same key
        key2 = crypto_utils.derive_key_from_password(password, salt)
        assert key == key2
        
    def test_hash_operations(self, crypto_utils):
        """Test cryptographic hashing"""
        test_data = b"test data for hashing operations"
        
        # Test different hash algorithms
        algorithms = ['sha256', 'sha512']
        
        for algorithm in algorithms:
            hash_result = crypto_utils.hash_data(test_data, algorithm)
            assert len(hash_result) > 0
            assert isinstance(hash_result, bytes)
            
            # Same data should produce same hash
            hash_result2 = crypto_utils.hash_data(test_data, algorithm)
            assert hash_result == hash_result2
            
    def test_hmac_operations(self, crypto_utils):
        """Test HMAC signing and verification"""
        test_data = b"data to sign with HMAC"
        key = crypto_utils.generate_secure_random(32)
        
        # Generate signature
        signature = crypto_utils.hmac_sign(test_data, key)
        assert len(signature) > 0
        assert isinstance(signature, bytes)
        
        # Verify valid signature
        assert crypto_utils.hmac_verify(test_data, signature, key) == True
        
        # Verify invalid signature fails
        wrong_key = crypto_utils.generate_secure_random(32)
        assert crypto_utils.hmac_verify(test_data, signature, wrong_key) == False
        
    def test_constant_time_comparison(self, crypto_utils):
        """Test constant-time comparison"""
        # Test equal strings
        a = b"test_string_constant_time"
        b = b"test_string_constant_time"
        assert crypto_utils.constant_time_compare(a, b) == True
        
        # Test different strings
        c = b"different_string_constant"
        assert crypto_utils.constant_time_compare(a, c) == False
        
    def test_symmetric_encryption(self, crypto_utils):
        """Test symmetric encryption and decryption"""
        plaintext = b"secret message for symmetric encryption test"
        key = crypto_utils.generate_secure_random(32)
        
        # Encrypt
        ciphertext, tag, nonce = crypto_utils.encrypt_symmetric(plaintext, key)
        
        assert len(ciphertext) > 0
        assert len(tag) > 0
        assert len(nonce) > 0
        
        # Decrypt with correct data
        decrypted = crypto_utils.decrypt_symmetric(ciphertext, key, nonce, tag)
        assert decrypted == plaintext


class TestPerformanceMonitor:
    """Test cases for PerformanceMonitor class"""
    
    @pytest.fixture
    def performance_monitor(self):
        """Create PerformanceMonitor instance"""
        monitor = PerformanceMonitor(
            enable_memory_monitoring=True,
            enable_cpu_monitoring=True
        )
        return monitor
    
    def test_initialization(self, performance_monitor):
        """Test PerformanceMonitor initialization"""
        assert performance_monitor.enable_memory_monitoring == True
        assert performance_monitor.enable_cpu_monitoring == True
        
    def test_operation_measurement(self, performance_monitor):
        """Test operation performance measurement"""
        # Measure a fast operation
        with performance_monitor.measure_operation('fast_operation'):
            time.sleep(0.01)
        
        # Measure a slower operation
        with performance_monitor.measure_operation('slow_operation'):
            time.sleep(0.1)
        
        # Verify statistics were recorded
        assert 'fast_operation' in performance_monitor.operation_stats
        assert 'slow_operation' in performance_monitor.operation_stats
        
    def test_performance_report(self, performance_monitor):
        """Test performance report generation"""
        # Generate some activity
        for i in range(3):
            with performance_monitor.measure_operation(f'test_op_{i}'):
                time.sleep(0.01)
        
        # Generate report
        report = performance_monitor.get_performance_report()
        
        assert 'timestamp' in report
        assert 'operation_stats' in report
        assert isinstance(report, dict)


class TestDataUtils:
    """Test cases for DataUtils class"""
    
    @pytest.fixture
    def data_utils(self):
        """Create DataUtils instance"""
        return DataUtils()
    
    def test_serialization_formats(self, data_utils):
        """Test different serialization formats"""
        test_data = {
            'string': 'test_value',
            'number': 42,
            'list': [1, 2, 3, 4, 5],
            'nested': {'key': 'value', 'array': [1, 2, 3]}
        }
        
        # Test JSON serialization
        json_data = data_utils.serialize_data(test_data, 'json')
        deserialized_json = data_utils.deserialize_data(json_data, 'json')
        assert deserialized_json == test_data
        
        # Test msgpack if available
        if hasattr(data_utils, 'serialize_data_msgpack'):
            msgpack_data = data_utils.serialize_data_msgpack(test_data)
            deserialized_msgpack = data_utils.deserialize_data_msgpack(msgpack_data)
            assert deserialized_msgpack == test_data
            
    def test_compression(self, data_utils):
        """Test data compression"""
        # Generate compressible data
        test_data = b"ABCDEFGH" * 100  # 800 bytes of repeating data
        
        # Test compression
        compressed = data_utils.compress_data(test_data)
        decompressed = data_utils.decompress_data(compressed)
        
        assert decompressed == test_data
        
    def test_data_validation(self, data_utils):
        """Test data structure validation"""
        # Simple validation test
        valid_data = {'name': 'test', 'value': 123}
        
        # Basic validation if method exists
        if hasattr(data_utils, 'validate_data'):
            is_valid = data_utils.validate_data(valid_data)
            assert is_valid == True


class TestErrorHandler:
    """Test cases for ErrorHandler class"""
    
    @pytest.fixture
    def error_handler(self):
        """Create ErrorHandler instance"""
        return ErrorHandler(max_retries=3, base_delay=0.1)
    
    def test_initialization(self, error_handler):
        """Test ErrorHandler initialization"""
        assert error_handler.max_retries == 3
        assert error_handler.base_delay == 0.1
        
    def test_error_handling_context(self, error_handler):
        """Test error handling context manager"""
        # Successful operation
        with error_handler.handle_errors('successful_operation'):
            result = "operation completed successfully"
        
        # Failing operation
        with pytest.raises(ValueError):
            with error_handler.handle_errors('failing_operation'):
                raise ValueError("Test error for error handling")
                
    def test_retry_logic(self, error_handler):
        """Test retry logic with exponential backoff"""
        call_count = 0
        
        def failing_function():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise RuntimeError("Not ready yet")
            return "success after retries"
        
        # Should succeed after retries
        result = error_handler.retry_on_failure(failing_function)
        assert result == "success after retries"
        assert call_count == 2


# Integration tests for utility classes
class TestUtilsIntegration:
    """Integration tests for utility classes working together"""
    
    def test_crypto_with_data_utils(self):
        """Test integration between CryptoUtils and DataUtils"""
        crypto_utils = CryptoUtils(security_level=SecurityLevel.HIGH)
        data_utils = DataUtils()
        
        # Create test data
        original_data = {
            'sensitive_info': 'highly confidential data',
            'config': {'api_key': 'secret_12345', 'auth_token': 'token_abcde'}
        }
        
        # Serialize
        serialized = data_utils.serialize_data(original_data, 'json')
        
        # Encrypt
        key = crypto_utils.generate_secure_random(32)
        ciphertext, tag, nonce = crypto_utils.encrypt_symmetric(serialized, key)
        
        # Decrypt
        decrypted = crypto_utils.decrypt_symmetric(ciphertext, key, nonce, tag)
        deserialized = data_utils.deserialize_data(decrypted, 'json')
        
        assert deserialized == original_data
        
    def test_performance_monitoring_with_error_handling(self):
        """Test integration between PerformanceMonitor and ErrorHandler"""
        performance_monitor = PerformanceMonitor(
            enable_memory_monitoring=False,
            enable_cpu_monitoring=False
        )
        
        error_handler = ErrorHandler(max_retries=2, base_delay=0.1)
        
        @performance_monitor.track_method
        def monitored_function(should_fail=False):
            with performance_monitor.measure_operation('internal_operation'):
                time.sleep(0.01)
                if should_fail:
                    raise ValueError("Intentional failure")
                return "successful result"
        
        # Test successful operation
        with performance_monitor.measure_operation('integration_test_success'):
            result = monitored_function(should_fail=False)
            assert result == "successful result"
        
        # Test failing operation
        with pytest.raises(ValueError):
            with performance_monitor.measure_operation('integration_test_failure'):
                monitored_function(should_fail=True)