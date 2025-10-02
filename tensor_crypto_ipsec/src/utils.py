"""
utils.py
Utility Functions and Helper Classes for Tensor-Based Post-Quantum Cryptography

This module provides common utilities, helper functions, logging setup, performance
monitoring, configuration management, and system diagnostics for the tensor-based
cryptographic system.
"""

import os
import sys
import time
import json
import logging
import hashlib
import hmac
import platform
import psutil
import threading
import functools
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union, Callable
from dataclasses import dataclass, asdict
from pathlib import Path
import numpy as np
import secrets
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import tempfile
import shutil
import zipfile


# ===== CONFIGURATION MANAGEMENT =====

@dataclass
class SystemConfig:
    """System configuration parameters"""
    # Security settings
    security_level: str = 'standard'
    tensor_dimensions: Tuple[int, int] = (8, 8)
    encryption_layers: int = 4
    
    # Performance settings
    max_cache_size: int = 100
    worker_threads: int = 4
    packet_queue_size: int = 1000
    
    # Network settings
    listen_port: int = 8443
    connection_timeout: int = 30
    session_timeout: int = 3600
    heartbeat_interval: int = 60
    
    # Key management
    key_rotation_interval: int = 1800  # 30 minutes
    max_key_usage: int = 5000
    pbkdf2_iterations: int = 200000
    
    # Dictionary settings
    dictionary_size: int = 2048
    refresh_interval: int = 1800
    sync_timeout: int = 60
    
    # Logging
    log_level: str = 'INFO'
    log_file: Optional[str] = None
    log_rotation: bool = True
    
    # Directories
    data_dir: str = './data'
    cache_dir: str = './cache'
    log_dir: str = './logs'
    temp_dir: str = './temp'


class ConfigManager:
    """Configuration management with validation and persistence"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or 'tensor_crypto_config.json'
        self.config = SystemConfig()
        self.load_config()
    
    def load_config(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                
                # Update config with loaded values
                for key, value in config_data.items():
                    if hasattr(self.config, key):
                        # Handle tuple types
                        if key == 'tensor_dimensions' and isinstance(value, list):
                            setattr(self.config, key, tuple(value))
                        else:
                            setattr(self.config, key, value)
                
                print(f"Configuration loaded from {self.config_file}")
            except Exception as e:
                print(f"Error loading config: {e}")
    
    def save_config(self):
        """Save configuration to file"""
        try:
            config_dict = asdict(self.config)
            with open(self.config_file, 'w') as f:
                json.dump(config_dict, f, indent=2)
            print(f"Configuration saved to {self.config_file}")
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def update_config(self, **kwargs):
        """Update configuration parameters"""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
            else:
                print(f"Warning: Unknown config parameter '{key}'")
        self.save_config()
    
    def validate_config(self) -> bool:
        """Validate configuration parameters"""
        errors = []
        
        # Validate security level
        if self.config.security_level not in ['basic', 'standard', 'high']:
            errors.append("Invalid security_level")
        
        # Validate tensor dimensions
        if len(self.config.tensor_dimensions) != 2 or any(d <= 0 for d in self.config.tensor_dimensions):
            errors.append("Invalid tensor_dimensions")
        
        # Validate positive integers
        positive_int_fields = ['max_cache_size', 'worker_threads', 'listen_port', 
                              'connection_timeout', 'session_timeout', 'dictionary_size']
        for field in positive_int_fields:
            if getattr(self.config, field) <= 0:
                errors.append(f"Invalid {field}: must be positive")
        
        if errors:
            print("Configuration validation errors:")
            for error in errors:
                print(f"  - {error}")
            return False
        
        return True


# ===== LOGGING SETUP =====

class ColoredFormatter(logging.Formatter):
    """Colored log formatter for console output"""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'ENDC': '\033[0m'       # End color
    }
    
    def format(self, record):
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.COLORS['ENDC']}"
        return super().format(record)


def setup_logging(config: SystemConfig):
    """Setup logging configuration"""
    # Create directories
    if config.log_dir:
        os.makedirs(config.log_dir, exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, config.log_level.upper()))
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Console handler with colors
    console_handler = logging.StreamHandler()
    console_formatter = ColoredFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # File handler if specified
    if config.log_file:
        log_path = os.path.join(config.log_dir, config.log_file)
        
        if config.log_rotation:
            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(
                log_path, maxBytes=10*1024*1024, backupCount=5
            )
        else:
            file_handler = logging.FileHandler(log_path)
        
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
    
    logging.info("Logging configured successfully")


# ===== DEVICE FINGERPRINTING =====

def generate_device_fingerprint() -> str:
    """Generate unique device fingerprint"""
    try:
        # Collect hardware information
        fingerprint_data = {
            'platform': platform.system(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'architecture': platform.architecture(),
            'hostname': platform.node(),
            'python_version': platform.python_version(),
        }
        
        # Add CPU info
        try:
            fingerprint_data['cpu_count'] = psutil.cpu_count()
            fingerprint_data['cpu_freq'] = psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {}
        except:
            pass
        
        # Add memory info
        try:
            mem = psutil.virtual_memory()
            fingerprint_data['total_memory'] = mem.total
        except:
            pass
        
        # Add disk info
        try:
            disk = psutil.disk_usage('/')
            fingerprint_data['disk_total'] = disk.total
        except:
            pass
        
        # Add network info
        try:
            import uuid
            fingerprint_data['mac_address'] = uuid.getnode()
        except:
            pass
        
        # Create deterministic fingerprint
        fingerprint_json = json.dumps(fingerprint_data, sort_keys=True)
        fingerprint_hash = hashlib.sha256(fingerprint_json.encode()).hexdigest()
        
        return f"device_{fingerprint_hash[:24]}"
        
    except Exception as e:
        # Fallback fingerprint
        fallback = f"{platform.system()}_{platform.machine()}_{secrets.token_hex(8)}"
        return hashlib.sha256(fallback.encode()).hexdigest()[:24]


# ===== ENTROPY AND RANDOMNESS =====

def calculate_entropy(data: Union[bytes, np.ndarray, List]) -> float:
    """
    Calculate Shannon entropy of data
    
    Args:
        data: Input data for entropy calculation
        
    Returns:
        Entropy value in bits
    """
    if isinstance(data, np.ndarray):
        data = data.flatten()
    elif isinstance(data, bytes):
        data = list(data)
    
    if not data:
        return 0.0
    
    # Calculate frequency distribution
    from collections import Counter
    counts = Counter(data)
    
    # Calculate probabilities
    total = len(data)
    probabilities = [count / total for count in counts.values()]
    
    # Calculate Shannon entropy
    entropy = -sum(p * np.log2(p) for p in probabilities if p > 0)
    
    return entropy


def test_randomness(data: bytes, min_entropy: float = 6.0) -> Dict[str, Any]:
    """
    Test randomness quality of data
    
    Args:
        data: Data to test
        min_entropy: Minimum entropy threshold
        
    Returns:
        Dictionary with test results
    """
    results = {
        'data_length': len(data),
        'entropy': calculate_entropy(data),
        'entropy_passed': False,
        'unique_bytes': len(set(data)),
        'byte_distribution': {},
        'patterns': {},
        'overall_quality': 'poor'
    }
    
    # Entropy test
    results['entropy_passed'] = results['entropy'] >= min_entropy
    
    # Byte distribution test
    byte_counts = {}
    for byte_val in data:
        byte_counts[byte_val] = byte_counts.get(byte_val, 0) + 1
    
    # Calculate chi-square for uniform distribution test
    expected_count = len(data) / 256
    chi_square = sum((count - expected_count) ** 2 / expected_count 
                    for count in byte_counts.values())
    
    results['chi_square'] = chi_square
    results['uniform_distribution'] = chi_square < 293.25  # 95% confidence threshold
    
    # Pattern detection
    patterns = detect_patterns(data)
    results['patterns'] = patterns
    results['pattern_free'] = len(patterns) == 0
    
    # Overall quality assessment
    passed_tests = sum([
        results['entropy_passed'],
        results['uniform_distribution'],
        results['pattern_free'],
        results['unique_bytes'] > len(data) * 0.8  # At least 80% unique
    ])
    
    if passed_tests >= 3:
        results['overall_quality'] = 'good'
    elif passed_tests >= 2:
        results['overall_quality'] = 'fair'
    else:
        results['overall_quality'] = 'poor'
    
    return results


def detect_patterns(data: bytes, max_pattern_length: int = 8) -> Dict[str, int]:
    """Detect repeating patterns in data"""
    patterns = {}
    
    for pattern_length in range(2, min(max_pattern_length + 1, len(data) // 2)):
        pattern_counts = {}
        
        for i in range(len(data) - pattern_length + 1):
            pattern = data[i:i + pattern_length]
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
        
        # Find patterns that repeat more than expected by chance
        threshold = max(2, len(data) // (256 ** pattern_length) * 3)
        for pattern, count in pattern_counts.items():
            if count >= threshold:
                patterns[pattern.hex()] = count
    
    return patterns


# ===== PERFORMANCE MONITORING =====

@dataclass
class PerformanceMetrics:
    """Performance metrics container"""
    operation_counts: Dict[str, int]
    execution_times: Dict[str, List[float]]
    memory_usage: Dict[str, int]
    error_counts: Dict[str, int]
    start_time: datetime
    
    def __post_init__(self):
        if not hasattr(self, 'operation_counts'):
            self.operation_counts = {}
        if not hasattr(self, 'execution_times'):
            self.execution_times = {}
        if not hasattr(self, 'memory_usage'):
            self.memory_usage = {}
        if not hasattr(self, 'error_counts'):
            self.error_counts = {}


class PerformanceMonitor:
    """Thread-safe performance monitoring"""
    
    def __init__(self):
        self.metrics = PerformanceMetrics(
            operation_counts={},
            execution_times={},
            memory_usage={},
            error_counts={},
            start_time=datetime.now()
        )
        self._lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
    
    def record_operation(self, operation: str, execution_time: float = None):
        """Record operation execution"""
        with self._lock:
            self.metrics.operation_counts[operation] = \
                self.metrics.operation_counts.get(operation, 0) + 1
            
            if execution_time is not None:
                if operation not in self.metrics.execution_times:
                    self.metrics.execution_times[operation] = []
                self.metrics.execution_times[operation].append(execution_time)
    
    def record_error(self, error_type: str):
        """Record error occurrence"""
        with self._lock:
            self.metrics.error_counts[error_type] = \
                self.metrics.error_counts.get(error_type, 0) + 1
    
    def record_memory_usage(self, component: str, bytes_used: int):
        """Record memory usage"""
        with self._lock:
            self.metrics.memory_usage[component] = bytes_used
    
    @contextmanager
    def time_operation(self, operation: str):
        """Context manager for timing operations"""
        start_time = time.time()
        try:
            yield
        except Exception as e:
            self.record_error(type(e).__name__)
            raise
        finally:
            execution_time = time.time() - start_time
            self.record_operation(operation, execution_time)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get performance statistics"""
        with self._lock:
            stats = {
                'uptime_seconds': (datetime.now() - self.metrics.start_time).total_seconds(),
                'total_operations': sum(self.metrics.operation_counts.values()),
                'total_errors': sum(self.metrics.error_counts.values()),
                'operation_counts': dict(self.metrics.operation_counts),
                'error_counts': dict(self.metrics.error_counts),
                'memory_usage': dict(self.metrics.memory_usage),
                'timing_stats': {}
            }
            
            # Calculate timing statistics
            for op, times in self.metrics.execution_times.items():
                if times:
                    stats['timing_stats'][op] = {
                        'count': len(times),
                        'total_time': sum(times),
                        'avg_time': sum(times) / len(times),
                        'min_time': min(times),
                        'max_time': max(times)
                    }
            
            return stats
    
    def get_summary(self) -> str:
        """Get formatted performance summary"""
        stats = self.get_statistics()
        
        summary = f"""
Performance Summary:
  Uptime: {stats['uptime_seconds']:.1f} seconds
  Total Operations: {stats['total_operations']}
  Total Errors: {stats['total_errors']}
  Error Rate: {stats['total_errors']/max(stats['total_operations'], 1)*100:.2f}%
"""
        
        if stats['timing_stats']:
            summary += "\nTiming Statistics:\n"
            for op, timing in stats['timing_stats'].items():
                summary += f"  {op}: {timing['avg_time']*1000:.2f}ms avg ({timing['count']} ops)\n"
        
        if stats['memory_usage']:
            summary += "\nMemory Usage:\n"
            for component, usage in stats['memory_usage'].items():
                summary += f"  {component}: {usage/1024/1024:.1f}MB\n"
        
        return summary


def performance_timer(func):
    """Decorator for timing function execution"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        monitor = getattr(wrapper, '_monitor', None)
        if monitor is None:
            # Create a global monitor if none exists
            if not hasattr(performance_timer, '_global_monitor'):
                performance_timer._global_monitor = PerformanceMonitor()
            monitor = performance_timer._global_monitor
        
        with monitor.time_operation(func.__name__):
            return func(*args, **kwargs)
    
    return wrapper


# ===== TENSOR UTILITIES =====

def verify_tensor_integrity(tensor: np.ndarray, expected_shape: Tuple[int, ...] = None,
                          expected_dtype: np.dtype = None) -> bool:
    """
    Verify tensor integrity and properties
    
    Args:
        tensor: Tensor to verify
        expected_shape: Expected tensor shape
        expected_dtype: Expected data type
        
    Returns:
        True if tensor passes all checks
    """
    if not isinstance(tensor, np.ndarray):
        return False
    
    # Check shape
    if expected_shape and tensor.shape != expected_shape:
        return False
    
    # Check dtype
    if expected_dtype and tensor.dtype != expected_dtype:
        return False
    
    # Check for NaN or infinite values
    if np.any(np.isnan(tensor)) or np.any(np.isinf(tensor)):
        return False
    
    # Check for reasonable entropy (avoid all-zero or constant tensors)
    if tensor.size > 1:
        unique_values = len(np.unique(tensor))
        if unique_values < max(2, tensor.size // 4):
            return False
    
    return True


def normalize_tensor(tensor: np.ndarray, target_range: Tuple[float, float] = (-1.0, 1.0)) -> np.ndarray:
    """Normalize tensor values to target range"""
    min_val, max_val = target_range
    
    # Get current range
    current_min = np.min(tensor)
    current_max = np.max(tensor)
    
    if current_max == current_min:
        # Handle constant tensor
        return np.full_like(tensor, (min_val + max_val) / 2)
    
    # Normalize to [0, 1] then scale to target range
    normalized = (tensor - current_min) / (current_max - current_min)
    scaled = normalized * (max_val - min_val) + min_val
    
    return scaled


def tensor_to_hex_string(tensor: np.ndarray) -> str:
    """Convert tensor to hex string representation"""
    return tensor.tobytes().hex()


def hex_string_to_tensor(hex_string: str, shape: Tuple[int, ...], dtype: np.dtype = np.uint8) -> np.ndarray:
    """Convert hex string back to tensor"""
    byte_data = bytes.fromhex(hex_string)
    return np.frombuffer(byte_data, dtype=dtype).reshape(shape)


# ===== CRYPTOGRAPHIC UTILITIES =====

def secure_random_bytes(length: int) -> bytes:
    """Generate cryptographically secure random bytes"""
    return secrets.token_bytes(length)


def secure_random_int(min_val: int, max_val: int) -> int:
    """Generate cryptographically secure random integer"""
    return secrets.randbelow(max_val - min_val + 1) + min_val


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks"""
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0


def derive_key_from_password(password: str, salt: bytes, 
                           iterations: int = 200000, key_length: int = 32) -> bytes:
    """Derive cryptographic key from password using PBKDF2"""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    
    return kdf.derive(password.encode('utf-8'))


def calculate_hmac(key: bytes, data: bytes, algorithm: str = 'sha256') -> bytes:
    """Calculate HMAC for data integrity"""
    hash_map = {
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512,
        'sha1': hashlib.sha1
    }
    
    if algorithm not in hash_map:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    return hmac.new(key, data, hash_map[algorithm]).digest()


# ===== SYSTEM DIAGNOSTICS =====

def system_health_check() -> Dict[str, Any]:
    """Perform comprehensive system health check"""
    health_report = {
        'timestamp': datetime.now().isoformat(),
        'overall_status': 'healthy',
        'checks': {}
    }
    
    try:
        # CPU check
        cpu_percent = psutil.cpu_percent(interval=1)
        health_report['checks']['cpu'] = {
            'usage_percent': cpu_percent,
            'status': 'healthy' if cpu_percent < 80 else 'warning',
            'cores': psutil.cpu_count()
        }
        
        # Memory check
        memory = psutil.virtual_memory()
        health_report['checks']['memory'] = {
            'usage_percent': memory.percent,
            'available_gb': memory.available / (1024**3),
            'total_gb': memory.total / (1024**3),
            'status': 'healthy' if memory.percent < 85 else 'warning'
        }
        
        # Disk check
        disk = psutil.disk_usage('/')
        health_report['checks']['disk'] = {
            'usage_percent': disk.used / disk.total * 100,
            'free_gb': disk.free / (1024**3),
            'total_gb': disk.total / (1024**3),
            'status': 'healthy' if disk.used / disk.total < 0.9 else 'warning'
        }
        
        # Network interfaces
        net_interfaces = psutil.net_if_addrs()
        health_report['checks']['network'] = {
            'interfaces': list(net_interfaces.keys()),
            'status': 'healthy' if net_interfaces else 'error'
        }
        
        # Check for any warnings or errors
        warning_checks = [check for check in health_report['checks'].values() 
                         if check.get('status') == 'warning']
        error_checks = [check for check in health_report['checks'].values() 
                       if check.get('status') == 'error']
        
        if error_checks:
            health_report['overall_status'] = 'error'
        elif warning_checks:
            health_report['overall_status'] = 'warning'
        
    except Exception as e:
        health_report['overall_status'] = 'error'
        health_report['error'] = str(e)
    
    return health_report


def check_dependencies() -> Dict[str, bool]:
    """Check if required dependencies are available"""
    dependencies = {
        'numpy': False,
        'tensorflow': False,
        'cryptography': False,
        'psutil': False,
        'sqlite3': False
    }
    
    try:
        import numpy
        dependencies['numpy'] = True
    except ImportError:
        pass
    
    try:
        import tensorflow
        dependencies['tensorflow'] = True
    except ImportError:
        pass
    
    try:
        import cryptography
        dependencies['cryptography'] = True
    except ImportError:
        pass
    
    try:
        import psutil
        dependencies['psutil'] = True
    except ImportError:
        pass
    
    try:
        import sqlite3
        dependencies['sqlite3'] = True
    except ImportError:
        pass
    
    return dependencies


# ===== FILE AND DIRECTORY UTILITIES =====

def ensure_directory_exists(path: str) -> bool:
    """Ensure directory exists, create if necessary"""
    try:
        os.makedirs(path, exist_ok=True)
        return True
    except Exception as e:
        logging.error(f"Failed to create directory {path}: {e}")
        return False


def safe_file_write(filepath: str, data: Union[str, bytes], backup: bool = True) -> bool:
    """Safely write file with atomic operation and optional backup"""
    try:
        # Create backup if requested and file exists
        if backup and os.path.exists(filepath):
            backup_path = f"{filepath}.backup_{int(time.time())}"
            shutil.copy2(filepath, backup_path)
        
        # Write to temporary file first
        temp_path = f"{filepath}.tmp"
        mode = 'w' if isinstance(data, str) else 'wb'
        
        with open(temp_path, mode) as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        
        # Atomic rename
        if os.name == 'nt':  # Windows
            if os.path.exists(filepath):
                os.remove(filepath)
        os.rename(temp_path, filepath)
        
        return True
        
    except Exception as e:
        logging.error(f"Failed to write file {filepath}: {e}")
        # Cleanup temp file
        if os.path.exists(f"{filepath}.tmp"):
            os.remove(f"{filepath}.tmp")
        return False


def secure_delete_file(filepath: str, passes: int = 3) -> bool:
    """Securely delete file by overwriting with random data"""
    try:
        if not os.path.exists(filepath):
            return True
        
        file_size = os.path.getsize(filepath)
        
        with open(filepath, 'rb+') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
        
        os.remove(filepath)
        return True
        
    except Exception as e:
        logging.error(f"Failed to securely delete {filepath}: {e}")
        return False


def create_backup_archive(source_dir: str, backup_path: str, 
                         compression: bool = True) -> bool:
    """Create backup archive of directory"""
    try:
        if compression:
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(source_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arc_path = os.path.relpath(file_path, source_dir)
                        zipf.write(file_path, arc_path)
        else:
            shutil.make_archive(backup_path.replace('.zip', ''), 'zip', source_dir)
        
        return True
        
    except Exception as e:
        logging.error(f"Failed to create backup archive: {e}")
        return False


# ===== THREAD UTILITIES =====

class ThreadSafeCounter:
    """Thread-safe counter"""
    
    def __init__(self, initial_value: int = 0):
        self._value = initial_value
        self._lock = threading.Lock()
    
    def increment(self, amount: int = 1) -> int:
        with self._lock:
            self._value += amount
            return self._value
    
    def decrement(self, amount: int = 1) -> int:
        with self._lock:
            self._value -= amount
            return self._value
    
    def get_value(self) -> int:
        with self._lock:
            return self._value
    
    def set_value(self, value: int) -> int:
        with self._lock:
            self._value = value
            return self._value


class RateLimiter:
    """Thread-safe rate limiter"""
    
    def __init__(self, max_calls: int, time_window: float):
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls = []
        self._lock = threading.Lock()
    
    def is_allowed(self) -> bool:
        """Check if call is allowed under rate limit"""
        with self._lock:
            now = time.time()
            
            # Remove old calls outside time window
            self.calls = [call_time for call_time in self.calls 
                         if now - call_time < self.time_window]
            
            # Check if under limit
            if len(self.calls) < self.max_calls:
                self.calls.append(now)
                return True
            
            return False
    
    def wait_time(self) -> float:
        """Get time to wait before next allowed call"""
        with self._lock:
            if len(self.calls) < self.max_calls:
                return 0.0
            
            oldest_call = min(self.calls)
            return max(0.0, self.time_window - (time.time() - oldest_call))


# ===== TESTING UTILITIES =====

def create_test_data(data_type: str, size: int) -> Any:
    """Create test data of specified type and size"""
    if data_type == 'random_bytes':
        return os.urandom(size)
    elif data_type == 'random_tensor':
        return np.random.randint(0, 256, size, dtype=np.uint8)
    elif data_type == 'text':
        chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        return ''.join(secrets.choice(chars) for _ in range(size))
    elif data_type == 'structured':
        return {'test_data': list(range(size)), 'timestamp': time.time()}
    else:
        raise ValueError(f"Unknown data type: {data_type}")


def benchmark_function(func: Callable, *args, iterations: int = 1000, **kwargs) -> Dict[str, float]:
    """Benchmark function execution"""
    times = []
    
    for _ in range(iterations):
        start_time = time.perf_counter()
        try:
            result = func(*args, **kwargs)
        except Exception as e:
            logging.error(f"Benchmark function failed: {e}")
            return {'error': str(e)}
        end_time = time.perf_counter()
        times.append(end_time - start_time)
    
    return {
        'iterations': iterations,
        'total_time': sum(times),
        'avg_time': sum(times) / len(times),
        'min_time': min(times),
        'max_time': max(times),
        'std_dev': np.std(times) if len(times) > 1 else 0.0
    }


# ===== MODULE INITIALIZATION =====

# Global performance monitor instance
global_performance_monitor = PerformanceMonitor()

# Global configuration manager
global_config_manager = ConfigManager()


def initialize_system(config_file: Optional[str] = None) -> bool:
    """Initialize the complete system with configuration"""
    global global_config_manager
    
    try:
        # Load configuration
        if config_file:
            global_config_manager = ConfigManager(config_file)
        
        # Validate configuration
        if not global_config_manager.validate_config():
            return False
        
        # Setup logging
        setup_logging(global_config_manager.config)
        
        # Create directories
        directories = [
            global_config_manager.config.data_dir,
            global_config_manager.config.cache_dir,
            global_config_manager.config.log_dir,
            global_config_manager.config.temp_dir
        ]
        
        for directory in directories:
            if not ensure_directory_exists(directory):
                return False
        
        # Check dependencies
        deps = check_dependencies()
        missing_deps = [dep for dep, available in deps.items() if not available]
        
        if missing_deps:
            logging.warning(f"Missing dependencies: {missing_deps}")
        
        # System health check
        health = system_health_check()
        logging.info(f"System health: {health['overall_status']}")
        
        logging.info("System initialization completed successfully")
        return True
        
    except Exception as e:
        logging.error(f"System initialization failed: {e}")
        return False


if __name__ == "__main__":
    # Example usage
    if initialize_system():
        print("System initialized successfully")
        
        # Example performance monitoring
        with global_performance_monitor.time_operation('example_operation'):
            time.sleep(0.1)
        
        print(global_performance_monitor.get_summary())
    else:
        print("System initialization failed")
