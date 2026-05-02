# [file name]: src/__init__.py
"""
Tensor Crypto IPSec - Quantum-Resistant Encryption System
========================================================

A novel approach to encryption using tensor mathematics and AI-generated logic chains
for quantum-resistant security in network communications.

Features:
---------
- Quantum-resistant tensor-based cryptography
- AI-generated mathematical transformations
- Advanced key management with forward secrecy
- Secure dictionary management for session state
- Router-level integration for IPSec replacement
- Comprehensive performance monitoring and security auditing

Modules:
--------
- ai_logic: AI-driven logic generation for cryptographic transformations
- key_management: Secure key generation, derivation, and lifecycle management
- tensor_engine: Multi-dimensional tensor operations for encryption
- dictionary_manager: Secure session state and dictionary management
- router_interface: Network-level integration and packet processing
- utils: Cryptographic utilities, performance monitoring, and security auditing

Usage:
------
>>> from tensor_crypto_ipsec import (
...     AILogicGenerator, KeyManager, TensorEncryptionEngine,
...     DictionaryManager, RouterInterface, CryptoUtils,
...     PerformanceMonitor, DataUtils, SecurityAuditor, ErrorHandler,
...     create_router_interface, create_key_manager, create_dictionary_manager,
...     create_tensor_engine, create_ai_logic_generator
... )

>>> # Create AI logic generator
>>> ai_gen = create_ai_logic_generator(security='quantum')

>>> # Initialize key management
>>> key_mgr = create_key_manager(security_level='high')

>>> # Create tensor encryption engine
>>> tensor_engine = create_tensor_engine(security_level='high')

>>> # Set up dictionary manager
>>> dict_mgr = create_dictionary_manager(device_id='router_1', security_level='high')

>>> # Initialize router interface
>>> router = create_router_interface(
...     interface_name='eth0',
...     security_level='high'
... )

>>> # Initialize utilities
>>> crypto_utils = CryptoUtils()
>>> perf_monitor = PerformanceMonitor()
>>> security_auditor = SecurityAuditor()

Security Levels:
----------------
- basic: 128-bit security (development/testing)
- standard: 192-bit security (general use)
- high: 256-bit security (enterprise)
- quantum: 512-bit security (post-quantum resistance)

Version: 1.0.2
Author: Tensor Crypto IPSec Team
License: Proprietary
"""

__version__ = "1.0.2"
__author__ = "Tensor Crypto IPSec Team"
__license__ = "Proprietary"

import logging
import time
from typing import Dict, List, Tuple, Optional, Any, Union
from enum import Enum
from contextlib import contextmanager

# Import main classes from modules
from .ai_logic import AILogicGenerator, LogicType, ComplexityLevel, LogicMetadata
from .key_management import KeyManager, KeyType, KeyStatus, SecurityLevel as KeySecurityLevel
from .tensor_engine import TensorEncryptionEngine, TensorDimension, SecurityLevel as TensorSecurityLevel, SecurityError
from .dictionary_manager import DictionaryManager, DictionaryType, DictionaryStatus, SecurityError as DictSecurityError
from .router_interface import RouterInterface, ProtocolType, SessionState, TrafficPriority, RouterConfig

# Import utility classes and functions from utils
from .utils import (
    CryptoUtils, PerformanceMonitor, DataUtils, SecurityAuditor, ErrorHandler,
    SecurityLevel, CompressionAlgorithm, SerializationFormat,
    SecurityError as UtilsSecurityError, PerformanceError, ConfigurationError, CircuitOpenError,
    setup_logging, memory_cleanup, benchmark_operation, validate_configuration,
    create_backup, restore_backup, init_utils, cleanup_utils
)

# Import utility functions from other modules
from .ai_logic import create_ai_logic_generator
from .key_management import create_key_manager, generate_secure_random_key, derive_key_from_password
from .tensor_engine import create_tensor_engine, calculate_tensor_entropy, verify_tensor_cryptographic_properties
from .dictionary_manager import create_dictionary_manager, calculate_data_entropy, verify_dictionary_integrity
from .router_interface import create_router_interface, validate_ip_address, get_network_interfaces

# Package-level configuration
class Config:
    """Package configuration settings"""
    
    # Default security level
    DEFAULT_SECURITY_LEVEL = SecurityLevel.HIGH
    
    # Default tensor dimensions
    DEFAULT_TENSOR_DIMENSIONS = (8, 8)
    
    # Default buffer sizes
    DEFAULT_BUFFER_SIZE = 65536
    
    # Enable/disable debug features
    DEBUG = False
    
    # Performance monitoring
    ENABLE_PERFORMANCE_MONITORING = True
    
    # Security auditing
    ENABLE_SECURITY_AUDITING = True
    
    # Logging configuration
    LOG_LEVEL = logging.INFO
    LOG_FILE = None

# Package initialization function
def initialize_package(security_level: SecurityLevel = None,
                      enable_monitoring: bool = True,
                      enable_auditing: bool = True,
                      log_level: int = logging.INFO,
                      log_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Initialize the Tensor Crypto IPSec package with specified configuration
    
    Args:
        security_level: Security level for all components
        enable_monitoring: Enable performance monitoring
        enable_auditing: Enable security auditing
        log_level: Logging level
        log_file: Optional log file path
        
    Returns:
        Dictionary with initialized components
    """
    if security_level is None:
        security_level = Config.DEFAULT_SECURITY_LEVEL
    
    # Update configuration
    Config.DEFAULT_SECURITY_LEVEL = security_level
    Config.ENABLE_PERFORMANCE_MONITORING = enable_monitoring
    Config.ENABLE_SECURITY_AUDITING = enable_auditing
    Config.LOG_LEVEL = log_level
    Config.LOG_FILE = log_file
    
    # Setup logging
    setup_logging(log_level=log_level, log_file=log_file)
    
    # Create utility components
    security_level_str = security_level.value
    
    crypto_utils, perf_monitor, data_utils, security_auditor, error_handler = init_utils(
        security_level=security_level,
        enable_monitoring=enable_monitoring
    )
    
    # Create core components
    tensor_engine = create_tensor_engine(
        dimensions=Config.DEFAULT_TENSOR_DIMENSIONS,
        security_level=security_level_str
    )
    
    key_manager = create_key_manager(security_level=security_level_str)
    
    dictionary_manager = create_dictionary_manager(
        device_id="package_root",
        security_level=security_level_str
    )
    
    ai_logic = create_ai_logic_generator(
        complexity="advanced",
        security=security_level_str
    )
    
    logger.info(f"Tensor Crypto IPSec package initialized with {security_level.value} security level")
    
    return {
        'crypto_utils': crypto_utils,
        'performance_monitor': perf_monitor,
        'data_utils': data_utils,
        'security_auditor': security_auditor,
        'error_handler': error_handler,
        'tensor_engine': tensor_engine,
        'key_manager': key_manager,
        'dictionary_manager': dictionary_manager,
        'ai_logic_generator': ai_logic,
        'config': Config
    }

# Package cleanup function
def cleanup_package(components: Dict[str, Any] = None):
    """Cleanup package resources and shutdown components"""
    if components:
        for name, component in components.items():
            if hasattr(component, 'shutdown'):
                try:
                    component.shutdown()
                    logger.debug(f"Shutdown {name} successfully")
                except Exception as e:
                    logger.warning(f"Failed to shutdown {name}: {e}")
    
    # Cleanup utilities
    cleanup_utils()
    
    # Memory cleanup
    memory_cleanup()
    
    logger.info("Tensor Crypto IPSec package cleanup completed")

# Context manager for package usage
@contextmanager
def tensor_crypto_context(security_level: SecurityLevel = SecurityLevel.HIGH,
                         enable_monitoring: bool = True,
                         enable_auditing: bool = True):
    """
    Context manager for safe package usage with automatic cleanup
    
    Args:
        security_level: Security level for the context
        enable_monitoring: Enable performance monitoring
        enable_auditing: Enable security auditing
        
    Yields:
        Initialized components dictionary
    """
    components = None
    try:
        components = initialize_package(
            security_level=security_level,
            enable_monitoring=enable_monitoring,
            enable_auditing=enable_auditing
        )
        yield components
    except Exception as e:
        logger.error(f"Error in tensor crypto context: {e}")
        raise
    finally:
        if components:
            cleanup_package(components)

# Version information
def get_version_info() -> Dict[str, Any]:
    """
    Get detailed version information
    
    Returns:
        Version information dictionary
    """
    import sys
    import platform
    
    # Try to get dependency versions
    deps = {}
    try:
        import numpy as np
        deps['numpy'] = np.__version__
    except ImportError:
        deps['numpy'] = 'Not installed'
    
    try:
        import cryptography
        deps['cryptography'] = cryptography.__version__
    except ImportError:
        deps['cryptography'] = 'Not installed'
    
    try:
        import tensorflow as tf
        deps['tensorflow'] = tf.__version__
    except ImportError:
        deps['tensorflow'] = 'Not installed'
    
    try:
        import msgpack
        deps['msgpack'] = 'Available'
    except ImportError:
        deps['msgpack'] = 'Not installed'
    
    try:
        import scipy
        deps['scipy'] = scipy.__version__
    except ImportError:
        deps['scipy'] = 'Not installed'
    
    try:
        import numba
        deps['numba'] = numba.__version__
    except ImportError:
        deps['numba'] = 'Not installed'
    
    try:
        import argon2
        deps['argon2'] = 'Available'
    except ImportError:
        deps['argon2'] = 'Not installed'
    
    try:
        import psutil
        deps['psutil'] = psutil.__version__
    except ImportError:
        deps['psutil'] = 'Not installed'
    
    try:
        import GPUtil
        deps['gputil'] = 'Available'
    except ImportError:
        deps['gputil'] = 'Not installed'
    
    try:
        import cpuinfo
        deps['cpuinfo'] = 'Available'
    except ImportError:
        deps['cpuinfo'] = 'Not installed'
    
    return {
        'package_version': __version__,
        'python_version': sys.version,
        'platform': platform.platform(),
        'system': platform.system(),
        'architecture': platform.architecture()[0],
        'dependencies': deps
    }

# Security level validation
def validate_security_level(level: Union[str, SecurityLevel]) -> SecurityLevel:
    """
    Validate and convert security level
    
    Args:
        level: Security level as string or enum
        
    Returns:
        Validated SecurityLevel enum
    """
    if isinstance(level, str):
        try:
            return SecurityLevel(level.lower())
        except ValueError:
            raise ValueError(f"Invalid security level: {level}. Must be one of: {[e.value for e in SecurityLevel]}")
    elif isinstance(level, SecurityLevel):
        return level
    else:
        raise TypeError(f"Security level must be str or SecurityLevel, got {type(level)}")

# Performance benchmarking
def benchmark_system_operations(iterations: int = 100) -> Dict[str, Any]:
    """
    Run comprehensive system performance benchmarks
    
    Args:
        iterations: Number of iterations per benchmark
        
    Returns:
        Benchmark results
    """
    results = {}
    
    # Benchmark cryptographic operations
    def crypto_benchmark():
        crypto = CryptoUtils()
        test_data = b"test_data_for_benchmarking" * 100
        key = generate_secure_random_key(32)
        nonce, ciphertext, tag = crypto.encrypt_symmetric(test_data, key)
        crypto.decrypt_symmetric(ciphertext, key, nonce, tag)
    
    results['crypto_operations'] = benchmark_operation(crypto_benchmark, iterations=iterations)
    
    # Benchmark tensor operations
    def tensor_benchmark():
        engine = create_tensor_engine()
        test_data = b"test_data" * 10
        session_tensor = engine.generate_session_tensor("benchmark", "test_device")
        encrypted, metadata = engine.encrypt_data(test_data, session_tensor)
        engine.decrypt_data(encrypted, session_tensor, metadata)
    
    results['tensor_operations'] = benchmark_operation(tensor_benchmark, iterations=iterations)
    
    # Benchmark AI logic generation
    def ai_benchmark():
        ai_gen = create_ai_logic_generator()
        ai_gen.generate_session_logic("benchmark", "test_device", use_cache=False)
    
    results['ai_operations'] = benchmark_operation(ai_benchmark, iterations=iterations)
    
    return results

# Security audit function
def perform_comprehensive_audit(components: Dict[str, Any]) -> Dict[str, Any]:
    """
    Perform comprehensive security audit on all components
    
    Args:
        components: Dictionary of initialized components
        
    Returns:
        Audit results
    """
    audit_results = {}
    
    # Audit cryptographic configuration
    crypto_config = {
        'key_length': 256,
        'hash_algorithm': 'sha3_512',
        'random_source': 'secrets',
        'debug_mode': Config.DEBUG
    }
    
    if 'security_auditor' in components:
        crypto_audit = components['security_auditor'].perform_security_audit(crypto_config)
        audit_results['cryptography'] = crypto_audit
    
    # Audit system configuration
    system_config = {
        'debug_mode': Config.DEBUG,
        'allow_insecure_protocols': False,
        'min_password_length': 16,
        'data_encryption': True,
        'access_controls': True
    }
    
    if 'security_auditor' in components:
        system_audit = components['security_auditor'].perform_security_audit(system_config)
        audit_results['system'] = system_audit
    
    # Get performance metrics
    if 'performance_monitor' in components:
        performance_report = components['performance_monitor'].get_performance_report()
        audit_results['performance'] = performance_report
    
    return audit_results

# Export all public classes and functions
__all__ = [
    # AI Logic
    'AILogicGenerator', 'LogicType', 'ComplexityLevel', 'LogicMetadata', 'create_ai_logic_generator',
    
    # Key Management
    'KeyManager', 'KeyType', 'KeyStatus', 'KeySecurityLevel', 'create_key_manager', 
    'generate_secure_random_key', 'derive_key_from_password',
    
    # Tensor Engine
    'TensorEncryptionEngine', 'TensorDimension', 'TensorSecurityLevel', 'create_tensor_engine',
    'calculate_tensor_entropy', 'verify_tensor_cryptographic_properties',
    
    # Dictionary Management
    'DictionaryManager', 'DictionaryType', 'DictionaryStatus', 'create_dictionary_manager',
    'calculate_data_entropy', 'verify_dictionary_integrity',
    
    # Router Interface
    'RouterInterface', 'ProtocolType', 'SessionState', 'TrafficPriority', 'RouterConfig',
    'create_router_interface', 'validate_ip_address', 'get_network_interfaces',
    
    # Utilities
    'CryptoUtils', 'PerformanceMonitor', 'DataUtils', 'SecurityAuditor', 'ErrorHandler',
    'SecurityLevel', 'CompressionAlgorithm', 'SerializationFormat',
    'setup_logging', 'memory_cleanup', 'benchmark_operation', 'validate_configuration',
    'create_backup', 'restore_backup', 'init_utils', 'cleanup_utils',
    
    # Exceptions
    'SecurityError', 'UtilsSecurityError', 'DictSecurityError', 'PerformanceError', 
    'ConfigurationError', 'CircuitOpenError',
    
    # Configuration and initialization
    'Config', 'initialize_package', 'cleanup_package', 'tensor_crypto_context',
    'get_version_info', 'validate_security_level', 'benchmark_system_operations',
    'perform_comprehensive_audit'
]

# Package initialization
try:
    # Set up package-level logging
    import logging
    logging.getLogger(__name__).addHandler(logging.NullHandler())
    
    # Import required dependencies
    import numpy as np
    import cryptography
    import scipy
    
    # Try to import optional dependencies
    try:
        import tensorflow as tf
    except ImportError:
        logger.warning("TensorFlow not available, some AI features may be limited")
    
    try:
        import msgpack
    except ImportError:
        logger.warning("msgpack not available, using fallback serialization")
    
    try:
        import numba
    except ImportError:
        logger.warning("numba not available, some operations may be slower")
    
    try:
        import argon2
    except ImportError:
        logger.warning("argon2 not available, using alternative KDF")
    
    try:
        import psutil
    except ImportError:
        logger.warning("psutil not available, system monitoring limited")
    
    try:
        import GPUtil
    except ImportError:
        logger.warning("GPUtil not available, GPU monitoring disabled")
    
    try:
        import cpuinfo
    except ImportError:
        logger.warning("cpuinfo not available, CPU info limited")
    
    logger = logging.getLogger(__name__)
    logger.info(f"Tensor Crypto IPSec v{__version__} initialized successfully")
    
except Exception as e:
    logging.error(f"Failed to initialize Tensor Crypto IPSec package: {e}")
    raise