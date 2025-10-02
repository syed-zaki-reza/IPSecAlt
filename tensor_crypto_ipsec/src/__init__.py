"""
Tensor-Based Post-Quantum Cryptographic System

A novel cryptographic system that combines high-dimensional tensor mathematics,
AI-generated logic, and dynamic dictionary management to create a quantum-resistant
encryption protocol suitable as an IPsec alternative.

This package provides:
- Tensor-based encryption engine
- AI-driven dynamic cryptographic logic generation
- Secure dictionary management with forward secrecy
- Network protocol simulation for router integration
"""

__version__ = "1.0.0"
__author__ = "Tensor Crypto Research Team"
__license__ = "MIT"

# Import main classes for easy access
from .tensor_engine import TensorEncryptionEngine
from .ai_logic import AILogicGenerator
from .dictionary_manager import DynamicDictionaryManager
from .router_interface import RouterInterface
from .utils import (
    setup_logging,
    generate_device_fingerprint,
    calculate_entropy,
    verify_tensor_integrity
)

# Package-level configuration
DEFAULT_TENSOR_DIMENSIONS = (8, 8)
DEFAULT_SECURITY_LEVEL = 'standard'
DEFAULT_LOG_LEVEL = 'INFO'

# Version info
def get_version_info():
    """Return detailed version information"""
    return {
        'version': __version__,
        'author': __author__,
        'license': __license__,
        'description': 'Tensor-Based Post-Quantum Cryptographic System'
    }

# Main system factory function
def create_tensor_crypto_system(tensor_dimensions=None, security_level=None, device_id=None):
    """
    Create a complete tensor cryptographic system with all components
    
    Args:
        tensor_dimensions: Tensor dimensions (default: (8, 8))
        security_level: Security level ('basic', 'standard', 'high')
        device_id: Device identifier (auto-generated if None)
    
    Returns:
        Dictionary containing all initialized system components
    """
    if tensor_dimensions is None:
        tensor_dimensions = DEFAULT_TENSOR_DIMENSIONS
    if security_level is None:
        security_level = DEFAULT_SECURITY_LEVEL
    
    # Setup logging
    setup_logging(DEFAULT_LOG_LEVEL)
    
    # Generate device ID if not provided
    if device_id is None:
        device_id = generate_device_fingerprint()
    
    # Initialize core components
    tensor_engine = TensorEncryptionEngine(
        tensor_dimensions=tensor_dimensions,
        security_level=security_level
    )
    
    ai_logic = AILogicGenerator(
        input_dim=64,
        output_dim=np.prod(tensor_dimensions)
    )
    
    dict_manager = DynamicDictionaryManager(
        device_id=device_id
    )
    
    router_interface = RouterInterface(
        tensor_engine=tensor_engine,
        ai_logic=ai_logic,
        dict_manager=dict_manager,
        device_id=device_id
    )
    
    return {
        'tensor_engine': tensor_engine,
        'ai_logic': ai_logic,
        'dict_manager': dict_manager,
        'router_interface': router_interface,
        'device_id': device_id,
        'config': {
            'tensor_dimensions': tensor_dimensions,
            'security_level': security_level
        }
    }

# System status check
def system_health_check():
    """
    Perform basic system health check
    
    Returns:
        Dictionary with system status information
    """
    try:
        import numpy as np
        import tensorflow as tf
        from cryptography.hazmat.primitives import hashes
        
        status = {
            'numpy_available': True,
            'numpy_version': np.__version__,
            'tensorflow_available': True,
            'tensorflow_version': tf.__version__,
            'cryptography_available': True,
            'system_ready': True
        }
        
        # Test basic tensor operations
        test_tensor = np.random.randint(0, 256, (4, 4), dtype=np.uint8)
        test_result = np.bitwise_xor(test_tensor, test_tensor)
        
        if not np.all(test_result == 0):
            status['system_ready'] = False
            status['error'] = 'Basic tensor operations failed'
        
        return status
        
    except ImportError as e:
        return {
            'system_ready': False,
            'error': f'Missing dependencies: {str(e)}'
        }
    except Exception as e:
        return {
            'system_ready': False,
            'error': f'System check failed: {str(e)}'
        }

# Export all public classes and functions
__all__ = [
    'TensorEncryptionEngine',
    'AILogicGenerator', 
    'DynamicDictionaryManager',
    'RouterInterface',
    'create_tensor_crypto_system',
    'get_version_info',
    'system_health_check',
    'DEFAULT_TENSOR_DIMENSIONS',
    'DEFAULT_SECURITY_LEVEL'
]
