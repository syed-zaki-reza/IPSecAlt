# [file name]: src/tests/test_utils.py
"""
Comprehensive tests for Utility Classes
"""

import pytest
import tempfile
import numpy as np
from datetime import datetime, timedelta
import time

from src import (
    CryptoUtils, PerformanceMonitor, DataUtils, SecurityAuditor, ErrorHandler,
    SecurityLevel, CompressionAlgorithm, SerializationFormat,
    SecurityError, PerformanceError, CircuitOpenError
)


class TestCryptoUtils:
    """Test cases for CryptoUtils class"""
    
    def test_initialization(self):
        """Test CryptoUtils initialization"""
        crypto = CryptoUtils(security_level=SecurityLevel.HIGH)
        assert crypto.security_level == SecurityLevel.HIGH
        assert crypto.security_params['key_length'] == 64
        
    def test_secure_random_generation(self):
        """Test secure random number generation"""
        crypto = CryptoUtils()
        
        # Test different lengths
        for length in [16, 32, 64, 128]:
            random_data = crypto.generate_secure_random(length)
            assert len(random_data) == length
            assert isinstance(random_data, bytes)
            
            # Verify randomness (basic check)
            assert random_data != b'\x00' * length
        
    def test_password_key_derivation(self):
        """Test password-based key derivation"""
        crypto = CryptoUtils()
        password = "test_password_123"
        
        # Derive key with automatic salt
        key1, salt1 = crypto.derive_key_from_password(password)
        key2, salt2 = crypto.derive_key_from_password(password)
        
        # Same password with different salts should produce different keys
        assert key1 != key2
        assert salt1 != salt2
        
        # Derive key with specific salt
        key3, salt3 = crypto.derive_key_from_password(password, salt1)
        assert key3 == key1  # Same salt should produce same key
        
    def test_hash_operations(self):
        """Test cryptographic hashing"""
        crypto = CryptoUtils()
        test_data = b"test data for hashing"
        
        # Test different hash algorithms
        algorithms = ['sha256', 'sha512', 'sha3_256', 'sha3_512']
        
        for algorithm in algorithms:
            hash_result = crypto.hash_data(test_data, algorithm)
            assert len(hash_result) > 0
            assert isinstance(hash_result, bytes)
            
            # Same data should produce same hash
            hash_result2 = crypto.hash_data(test_data, algorithm)
            assert hash_result == hash_result2
            
    def test_hmac_operations(self):
        """Test HMAC signing and verification"""
        crypto = CryptoUtils()
        test_data = b"data to sign"
        key = crypto.generate_secure_random(32)
        
        # Generate signature
        signature = crypto.hmac_sign(test_data, key)
        assert len(signature) > 0
        
        # Verify valid signature
        assert crypto.hmac_verify(test_data, signature, key) == True
        
        # Verify invalid signature fails
        wrong_key = crypto.generate_secure_random(32)
        assert crypto.hmac_verify(test_data, signature, wrong_key) == False
        
        # Verify tampered data fails
        tampered_data = b"tampered data"
        assert crypto.hmac_verify(tampered_data, signature, key) == False
        
    def test_constant_time_comparison(self):
        """Test constant-time comparison"""
        crypto = CryptoUtils()
        
        # Test equal strings
        a = b"test_string"
        b = b"test_string"
        assert crypto.constant_time_compare(a, b) == True
        
        # Test different strings
        c = b"different_string"
        assert crypto.constant_time_compare(a, c) == False
        
        # Test different lengths
        d = b"short"
        assert crypto.constant_time_compare(a, d) == False
        
    def test_symmetric_encryption(self):
        """Test symmetric encryption and decryption"""
        crypto = CryptoUtils()
        plaintext = b"secret message for encryption"
        key = crypto.generate_secure_random(32)
        
        # Encrypt with associated data
        associated_data = b"metadata"
        nonce, ciphertext, tag = crypto.encrypt_symmetric(plaintext, key, associated_data)
        
        assert len(nonce) > 0
        assert len(ciphertext) > 0
        assert len(tag) > 0
        
        # Decrypt with correct data
        decrypted = crypto.decrypt_symmetric(ciphertext, key, nonce, tag, associated_data)
        assert decrypted == plaintext
        
        # Test decryption failure with wrong key
        wrong_key = crypto.generate_secure_random(32)
        with pytest.raises(SecurityError):
            crypto.decrypt_symmetric(ciphertext, wrong_key, nonce, tag, associated_data)
            
        # Test decryption failure with wrong associated data
        wrong_ad = b"wrong_metadata"
        with pytest.raises(SecurityError):
            crypto.decrypt_symmetric(ciphertext, key, nonce, tag, wrong_ad)


class TestPerformanceMonitor:
    """Test cases for PerformanceMonitor class"""
    
    def test_initialization(self):
        """Test PerformanceMonitor initialization"""
        monitor = PerformanceMonitor(
            enable_memory_monitoring=True,
            enable_cpu_monitoring=True
        )
        
        assert monitor.enable_memory_monitoring == True
        assert monitor.enable_cpu_monitoring == True
        assert len(monitor.operation_stats) == 0
        
    def test_operation_measurement(self):
        """Test operation performance measurement"""
        monitor = PerformanceMonitor(enable_memory_monitoring=False, enable_cpu_monitoring=False)
        
        # Measure a fast operation
        with monitor.measure_operation('fast_operation'):
            time.sleep(0.01)
        
        # Measure a slower operation
        with monitor.measure_operation('slow_operation'):
            time.sleep(0.1)
        
        # Verify statistics
        assert 'fast_operation' in monitor.operation_stats
        assert 'slow_operation' in monitor.operation_stats
        
        fast_stats = monitor.operation_stats['fast_operation']
        slow_stats = monitor.operation_stats['slow_operation']
        
        assert fast_stats.operation_count == 1
        assert slow_stats.operation_count == 1
        assert fast_stats.average_duration < slow_stats.average_duration
        
    def test_method_tracking_decorator(self):
        """Test method tracking decorator"""
        monitor = PerformanceMonitor(enable_memory_monitoring=False, enable_cpu_monitoring=False)
        
        @monitor.track_method
        def test_function(duration):
            time.sleep(duration)
            return "completed"
        
        # Call tracked function
        result = test_function(0.05)
        assert result == "completed"
        
        # Verify tracking
        operation_name = f"{__name__}.test_function"
        assert operation_name in monitor.operation_stats
        assert monitor.operation_stats[operation_name].success_count == 1
        
    def test_performance_report(self):
        """Test performance report generation"""
        monitor = PerformanceMonitor(enable_memory_monitoring=True, enable_cpu_monitoring=True)
        
        # Generate some activity
        for i in range(5):
            with monitor.measure_operation(f'test_op_{i}'):
                time.sleep(0.01)
        
        # Start monitoring to capture system metrics
        monitor.start_monitoring(interval_seconds=0.1)
        time.sleep(0.5)
        monitor.stop_monitoring()
        
        # Generate report
        report = monitor.get_performance_report()
        
        assert 'timestamp' in report
        assert 'operation_stats' in report
        assert 'memory_analysis' in report
        assert 'cpu_analysis' in report
        assert 'recommendations' in report
        
        # Verify operation stats are included
        assert len(report['operation_stats']) >= 5
        
    def test_memory_leak_detection(self):
        """Test memory leak detection"""
        monitor = PerformanceMonitor(enable_memory_monitoring=True, enable_cpu_monitoring=False)
        
        # Simulate memory growth pattern
        growing_memory = [100, 120, 140, 160, 180, 200, 220, 240, 260, 280]
        
        # Check leak detection
        leak_detected = monitor._check_memory_leak(growing_memory)
        assert leak_detected == True
        
        # Test stable memory pattern
        stable_memory = [100, 102, 98, 101, 99, 100, 101, 99, 100, 98]
        leak_detected = monitor._check_memory_leak(stable_memory)
        assert leak_detected == False


class TestDataUtils:
    """Test cases for DataUtils class"""
    
    def test_initialization(self):
        """Test DataUtils initialization"""
        data_utils = DataUtils(
            default_compression=CompressionAlgorithm.ZLIB,
            default_serialization=SerializationFormat.MSGPACK
        )
        
        assert data_utils.default_compression == CompressionAlgorithm.ZLIB
        assert data_utils.default_serialization == SerializationFormat.MSGPACK
        
    def test_serialization_formats(self):
        """Test different serialization formats"""
        data_utils = DataUtils()
        test_data = {
            'string': 'test_value',
            'number': 42,
            'list': [1, 2, 3, 4, 5],
            'nested': {'key': 'value'}
        }
        
        # Test MessagePack
        msgpack_data = data_utils.serialize_data(test_data, SerializationFormat.MSGPACK)
        deserialized_msgpack = data_utils.deserialize_data(msgpack_data, SerializationFormat.MSGPACK)
        assert deserialized_msgpack == test_data
        
        # Test JSON
        json_data = data_utils.serialize_data(test_data, SerializationFormat.JSON)
        deserialized_json = data_utils.deserialize_data(json_data, SerializationFormat.JSON)
        assert deserialized_json == test_data
        
        # Test Pickle
        pickle_data = data_utils.serialize_data(test_data, SerializationFormat.PICKLE)
        deserialized_pickle = data_utils.deserialize_data(pickle_data, SerializationFormat.PICKLE)
        assert deserialized_pickle == test_data
        
    def test_compression_algorithms(self):
        """Test different compression algorithms"""
        data_utils = DataUtils()
        
        # Generate compressible data (repeating pattern)
        test_data = b"ABCDEFGH" * 1000  # 8KB of repeating data
        
        # Test ZLIB compression
        if CompressionAlgorithm.ZLIB in data_utils.compression_libs:
            compressed = data_utils.compress_data(test_data, CompressionAlgorithm.ZLIB)
            decompressed = data_utils.decompress_data(compressed, CompressionAlgorithm.ZLIB)
            assert decompressed == test_data
            assert len(compressed) < len(test_data)  # Should compress well
            
        # Test no compression
        uncompressed = data_utils.compress_data(test_data, CompressionAlgorithm.NONE)
        assert uncompressed == test_data
        
    def test_data_entropy_calculation(self):
        """Test data entropy calculation"""
        data_utils = DataUtils()
        
        # High entropy data (random)
        random_data = os.urandom(1000)
        high_entropy = data_utils.calculate_data_entropy(random_data)
        assert high_entropy > 7.0  # Should be close to 8.0 for random data
        
        # Low entropy data (repeating pattern)
        repeating_data = b"A" * 1000
        low_entropy = data_utils.calculate_data_entropy(repeating_data)
        assert low_entropy < 1.0  # Should be very low
        
        # Empty data
        empty_entropy = data_utils.calculate_data_entropy(b"")
        assert empty_entropy == 0.0
        
    def test_data_validation(self):
        """Test data structure validation"""
        data_utils = DataUtils()
        
        schema = {
            'name': str,
            'age': int,
            'scores': list,
            'metadata': dict
        }
        
        # Valid data
        valid_data = {
            'name': 'John Doe',
            'age': 30,
            'scores': [95, 87, 92],
            'metadata': {'role': 'user'}
        }
        
        is_valid, errors = data_utils.validate_data_structure(valid_data, schema)
        assert is_valid == True
        assert len(errors) == 0
        
        # Invalid data
        invalid_data = {
            'name': 'Jane Doe',
            'age': 'thirty',  # Should be int
            'scores': [88, 91],  # This is ok
            # Missing 'metadata' key
        }
        
        is_valid, errors = data_utils.validate_data_structure(invalid_data, schema)
        assert is_valid == False
        assert len(errors) == 2  # Wrong type and missing key


class TestSecurityAuditor:
    """Test cases for SecurityAuditor class"""
    
    def test_initialization(self):
        """Test SecurityAuditor initialization"""
        auditor = SecurityAuditor(security_level=SecurityLevel.QUANTUM)
        assert auditor.security_level == SecurityLevel.QUANTUM
        assert len(auditor.vulnerability_database) > 0
        
    def test_security_audit(self):
        """Test comprehensive security audit"""
        auditor = SecurityAuditor(security_level=SecurityLevel.HIGH)
        
        # Test configuration
        config = {
            'key_length': 64,
            'hash_algorithm': 'sha512',
            'random_source': 'secrets',
            'debug_mode': False,
            'allow_insecure_protocols': False,
            'min_password_length': 12,
            'fips_compliant': True,
            'data_encryption': True,
            'access_controls': True
        }
        
        result = auditor.perform_security_audit(config)
        
        assert isinstance(result, SecurityAuditResult)
        assert result.security_level == SecurityLevel.HIGH
        assert result.overall_score > 0
        assert isinstance(result.vulnerabilities_found, list)
        assert isinstance(result.compliance_checks, dict)
        assert isinstance(result.recommendations, list)
        
    def test_vulnerability_detection(self):
        """Test specific vulnerability detection"""
        auditor = SecurityAuditor(security_level=SecurityLevel.HIGH)
        
        # Weak configuration
        weak_config = {
            'key_length': 16,  # Too short
            'hash_algorithm': 'md5',  # Weak algorithm
            'random_source': 'random',  # Insecure random
            'debug_mode': True,  # Debug in production
            'allow_insecure_protocols': True,  # Security risk
            'min_password_length': 4  # Weak passwords
        }
        
        result = auditor.perform_security_audit(weak_config)
        
        # Should find multiple vulnerabilities
        assert len(result.vulnerabilities_found) >= 4
        assert result.overall_score < 50  # Low security score
        
    def test_compliance_checking(self):
        """Test compliance standard checking"""
        auditor = SecurityAuditor(security_level=SecurityLevel.HIGH)
        
        # Compliant configuration
        compliant_config = {
            'key_length': 256,
            'fips_compliant': True,
            'data_encryption': True,
            'access_controls': True
        }
        
        result = auditor.perform_security_audit(compliant_config)
        
        # Should pass most compliance checks
        compliance_passed = sum(result.compliance_checks.values())
        assert compliance_passed >= 3  # Most checks should pass


class TestErrorHandler:
    """Test cases for ErrorHandler class"""
    
    def test_initialization(self):
        """Test ErrorHandler initialization"""
        handler = ErrorHandler(max_retries=5, base_delay=2.0)
        assert handler.max_retries == 5
        assert handler.base_delay == 2.0
        
    def test_error_handling_context(self):
        """Test error handling context manager"""
        handler = ErrorHandler()
        
        # Successful operation
        with handler.handle_errors('successful_operation'):
            result = "operation completed"
        
        # Failing operation
        with pytest.raises(ValueError):
            with handler.handle_errors('failing_operation'):
                raise ValueError("Test error")
        
        # Verify error statistics
        assert handler.error_stats['successful_operation']['success'] == 1
        assert handler.error_stats['failing_operation']['error'] == 1
        
    def test_retry_logic(self):
        """Test retry logic with exponential backoff"""
        handler = ErrorHandler(max_retries=3, base_delay=0.1)
        
        call_count = 0
        
        def failing_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise RuntimeError("Not ready yet")
            return "success"
        
        # Should succeed after retries
        result = handler.retry_on_failure(failing_function)
        assert result == "success"
        assert call_count == 3
        
    def test_circuit_breaker(self):
        """Test circuit breaker pattern"""
        handler = ErrorHandler(max_retries=2, base_delay=0.1)
        
        @handler.circuit_breaker('test_circuit', failure_threshold=2, timeout_seconds=1.0)
        def failing_function():
            raise RuntimeError("Always fails")
        
        # First calls should go through
        with pytest.raises(RuntimeError):
            failing_function()
        
        with pytest.raises(RuntimeError):
            failing_function()
        
        # Circuit should be open now
        with pytest.raises(CircuitOpenError):
            failing_function()
        
        # Wait for timeout
        time.sleep(1.1)
        
        # Circuit should be half-open, next failure should open it again
        with pytest.raises(RuntimeError):
            failing_function()


# Integration tests for utility classes
class TestUtilsIntegration:
    """Integration tests for utility classes working together"""
    
    def test_crypto_with_data_utils(self):
        """Test integration between CryptoUtils and DataUtils"""
        crypto = CryptoUtils()
        data_utils = DataUtils()
        
        # Create test data
        original_data = {
            'sensitive_info': 'secret_data',
            'config': {'api_key': '12345', 'token': 'abcde'}
        }
        
        # Serialize and compress
        serialized = data_utils.serialize_data(original_data)
        compressed = data_utils.compress_data(serialized)
        
        # Encrypt
        key = crypto.generate_secure_random(32)
        nonce, ciphertext, tag = crypto.encrypt_symmetric(compressed, key)
        
        # Decrypt and decompress
        decrypted = crypto.decrypt_symmetric(ciphertext, key, nonce, tag)
        decompressed = data_utils.decompress_data(decrypted)
        deserialized = data_utils.deserialize_data(decompressed)
        
        assert deserialized == original_data
        
    def test_performance_monitoring_with_error_handling(self):
        """Test integration between PerformanceMonitor and ErrorHandler"""
        perf_monitor = PerformanceMonitor(enable_memory_monitoring=False, enable_cpu_monitoring=False)
        error_handler = ErrorHandler(max_retries=2, base_delay=0.1)
        
        @perf_monitor.track_method
        @error_handler.circuit_breaker('monitored_function', failure_threshold=3)
        def monitored_function(should_fail=False):
            if should_fail:
                raise ValueError("Intentional failure")
            time.sleep(0.01)
            return "success"
        
        # Test successful operation
        with perf_monitor.measure_operation('integration_test'):
            result = monitored_function(should_fail=False)
            assert result == "success"
        
        # Test failing operation
        with pytest.raises(ValueError):
            with perf_monitor.measure_operation('integration_test_failure'):
                monitored_function(should_fail=True)
        
        # Verify both systems recorded the operations
        assert 'integration_test' in perf_monitor.operation_stats
        assert 'integration_test_failure' in perf_monitor.operation_stats
        assert 'monitored_function' in error_handler.circuit_breakers