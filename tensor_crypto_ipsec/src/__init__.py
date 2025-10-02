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
...     SecurityAuditor, PerformanceMonitor
... )

>>> # Create AI logic generator
>>> ai_gen = AILogicGenerator(security_level='quantum')

>>> # Initialize key management
>>> key_mgr = KeyManager(db_path='keys.db', security_level='high')

>>> # Create tensor encryption engine
>>> tensor_engine = TensorEncryptionEngine(tensor_dimensions=(8, 8))

>>> # Set up dictionary manager
>>> dict_mgr = DictionaryManager(db_path='dictionaries.db')

>>> # Initialize router interface
>>> router = RouterInterface(
...     interface_name='eth0',
...     key_manager=key_mgr,
...     dictionary_manager=dict_mgr,
...     tensor_engine=tensor_engine,
...     ai_logic_generator=ai_gen
... )

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
__email__ = "security@tensor-crypto-ipsec.com"

# Import main classes from modules
from .ai_logic import AILogicGenerator, LogicType, ComplexityLevel, LogicMetadata
from .key_management import KeyManager, KeyType, KeyStatus, SecurityLevel as KeySecurityLevel
from .tensor_engine import TensorEncryptionEngine, TensorDimension, SecurityLevel as TensorSecurityLevel
from .dictionary_manager import DictionaryManager, DictionaryType, DictionaryStatus
from .router_interface import RouterInterface, ProtocolType, SessionState, TrafficPriority
from .utils import (
    CryptoUtils, PerformanceMonitor, DataUtils, SecurityAuditor, ErrorHandler,
    SecurityLevel as UtilsSecurityLevel, CompressionAlgorithm, SerializationFormat,
    SecurityError, PerformanceError, ConfigurationError, CircuitOpenError
)

# Re-export common security level enum
SecurityLevel = UtilsSecurityLevel

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

# Package initialization function
def initialize_package(security_level: SecurityLevel = None,
                      enable_monitoring: bool = True,
                      enable_auditing: bool = True) -> Dict[str, Any]:
    """
    Initialize the Tensor Crypto IPSec package with specified configuration
    
    Args:
        security_level: Security level for all components
        enable_monitoring: Enable performance monitoring
        enable_auditing: Enable security auditing
        
    Returns:
        Dictionary with initialized components
    """
    if security_level is None:
        security_level = Config.DEFAULT_SECURITY_LEVEL
    
    # Update configuration
    Config.DEFAULT_SECURITY_LEVEL = security_level
    Config.ENABLE_PERFORMANCE_MONITORING = enable_monitoring
    Config.ENABLE_SECURITY_AUDITING = enable_auditing
    
    # Initialize utility components
    from .utils import init_utils
    crypto_utils, perf_monitor, data_utils, security_auditor, error_handler = init_utils(
        security_level=security_level,
        enable_monitoring=enable_monitoring
    )
    
    logger.info(f"Tensor Crypto IPSec package initialized with {security_level.value} security level")
    
    return {
        'crypto_utils': crypto_utils,
        'performance_monitor': perf_monitor,
        'data_utils': data_utils,
        'security_auditor': security_auditor,
        'error_handler': error_handler,
        'config': Config
    }

# Package cleanup function
def cleanup_package():
    """Cleanup package resources and shutdown components"""
    from .utils import cleanup_utils
    cleanup_utils()
    logger.info("Tensor Crypto IPSec package cleanup completed")

# Context manager for package usage
@contextmanager
def tensor_crypto_context(security_level: SecurityLevel = SecurityLevel.HIGH):
    """
    Context manager for safe package usage with automatic cleanup
    
    Args:
        security_level: Security level for the context
        
    Yields:
        Initialized components dictionary
    """
    components = None
    try:
        components = initialize_package(security_level=security_level)
        yield components
    except Exception as e:
        logger.error(f"Error in tensor crypto context: {e}")
        raise
    finally:
        if components:
            cleanup_package()

# Version information
def get_version_info() -> Dict[str, Any]:
    """
    Get detailed version information
    
    Returns:
        Version information dictionary
    """
    import sys
    import platform
    
    return {
        'package_version': __version__,
        'python_version': sys.version,
        'platform': platform.platform(),
        'system': platform.system(),
        'architecture': platform.architecture()[0],
        'dependencies': {
            'numpy': np.__version__,
            'cryptography': '2.8+',
            'tensorflow': '2.12+',
            'msgpack': '1.0.0+'
        }
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

# Export all public classes and functions
__all__ = [
    # AI Logic
    'AILogicGenerator', 'LogicType', 'ComplexityLevel', 'LogicMetadata',
    
    # Key Management
    'KeyManager', 'KeyType', 'KeyStatus', 'KeySecurityLevel',
    
    # Tensor Engine
    'TensorEncryptionEngine', 'TensorDimension', 'TensorSecurityLevel',
    
    # Dictionary Management
    'DictionaryManager', 'DictionaryType', 'DictionaryStatus',
    
    # Router Interface
    'RouterInterface', 'ProtocolType', 'SessionState', 'TrafficPriority',
    
    # Utilities
    'CryptoUtils', 'PerformanceMonitor', 'DataUtils', 'SecurityAuditor', 'ErrorHandler',
    'SecurityLevel', 'CompressionAlgorithm', 'SerializationFormat',
    
    # Exceptions
    'SecurityError', 'PerformanceError', 'ConfigurationError', 'CircuitOpenError',
    
    # Configuration and initialization
    'Config', 'initialize_package', 'cleanup_package', 'tensor_crypto_context',
    'get_version_info', 'validate_security_level'
]

# Package initialization
try:
    # Set up package-level logging
    import logging
    logging.getLogger(__name__).addHandler(logging.NullHandler())
    
    # Import numpy for tensor operations
    import numpy as np
    
    # Check for critical dependencies
    try:
        import cryptography
        import tensorflow as tf
        import msgpack
    except ImportError as e:
        raise ImportError(f"Missing critical dependency: {e}. Please install required packages.")
    
    logger = logging.getLogger(__name__)
    logger.info(f"Tensor Crypto IPSec v{__version__} initialized successfully")
    
except Exception as e:
    logging.error(f"Failed to initialize Tensor Crypto IPSec package: {e}")
    raise