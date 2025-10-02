# [file name]: src/tests/conftest.py
"""
Pytest configuration and fixtures for Tensor Crypto IPSec tests
"""

import pytest
import tempfile
import os
import sys
from typing import Dict, Any, Generator

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src import (
    AILogicGenerator, KeyManager, TensorEncryptionEngine,
    DictionaryManager, RouterInterface, CryptoUtils,
    PerformanceMonitor, SecurityAuditor, SecurityLevel
)

@pytest.fixture(scope="session")
def test_config() -> Dict[str, Any]:
    """Provide test configuration"""
    return {
        'security_level': 'high',
        'test_timeout': 30,
        'enable_long_tests': False,
        'test_data_dir': tempfile.mkdtemp(prefix='tensor_crypto_test_')
    }

@pytest.fixture
def temp_db_path() -> Generator[str, None, None]:
    """Create temporary database path"""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name
    yield db_path
    # Cleanup
    if os.path.exists(db_path):
        os.unlink(db_path)

@pytest.fixture
def crypto_utils() -> CryptoUtils:
    """Create CryptoUtils instance"""
    return CryptoUtils(security_level=SecurityLevel.HIGH)

@pytest.fixture
def ai_logic_generator() -> AILogicGenerator:
    """Create AILogicGenerator instance"""
    return AILogicGenerator(
        input_dim=64,
        output_dim=64,
        architecture='standard',
        security_level='high',
        training_mode=False
    )

@pytest.fixture
def key_manager(temp_db_path: str) -> KeyManager:
    """Create KeyManager instance"""
    return KeyManager(
        db_path=temp_db_path,
        device_id='test_device',
        security_level='high',
        auto_rotation=False
    )

@pytest.fixture
def tensor_engine() -> TensorEncryptionEngine:
    """Create TensorEncryptionEngine instance"""
    return TensorEncryptionEngine(
        tensor_dimensions=(8, 8),
        security_level='high'
    )

@pytest.fixture
def dictionary_manager(temp_db_path: str) -> DictionaryManager:
    """Create DictionaryManager instance"""
    return DictionaryManager(
        db_path=temp_db_path,
        device_id='test_device',
        security_level='high'
    )

@pytest.fixture
def performance_monitor() -> PerformanceMonitor:
    """Create PerformanceMonitor instance"""
    monitor = PerformanceMonitor(
        enable_memory_monitoring=True,
        enable_cpu_monitoring=True
    )
    monitor.start_monitoring(interval_seconds=1)
    yield monitor
    monitor.stop_monitoring()

@pytest.fixture
def security_auditor() -> SecurityAuditor:
    """Create SecurityAuditor instance"""
    return SecurityAuditor(security_level=SecurityLevel.HIGH)

@pytest.fixture
def sample_session_data() -> Dict[str, Any]:
    """Provide sample session data for testing"""
    return {
        'session_id': 'test_session_123',
        'device_fingerprint': 'test_device_abc',
        'timestamp': 1234567890.0,
        'additional_entropy': b'extra_random_data'
    }

@pytest.fixture
def sample_encryption_data() -> Dict[str, Any]:
    """Provide sample data for encryption tests"""
    return {
        'plaintext': b'This is a test message for encryption and decryption',
        'session_id': 'encryption_test_session',
        'device_fingerprint': 'test_device_encryption'
    }

# Custom pytest markers
def pytest_configure(config):
    """Register custom markers"""
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "security: mark test as security critical"
    )
    config.addinivalue_line(
        "markers", "performance: mark test as performance sensitive"
    )