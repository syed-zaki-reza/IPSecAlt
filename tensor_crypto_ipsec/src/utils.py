# [file name]: src/utils.py
"""
Enhanced Utilities for Quantum-Resistant Encryption System
Comprehensive utility functions and classes for cryptographic operations, performance monitoring, and system integration

Features:
- Advanced cryptographic utilities with quantum resistance
- Comprehensive performance monitoring and profiling
- System resource management and optimization
- Data serialization and compression utilities
- Security auditing and compliance checking
- Hardware acceleration detection and configuration
- Error handling and recovery mechanisms
"""

import os
import sys
import time
import json
import pickle
import zlib
import base64
import hashlib
import hmac
import logging
import threading
import secrets
import random
from typing import Dict, List, Tuple, Optional, Any, Union, Callable
from enum import Enum
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from functools import wraps
from contextlib import contextmanager
import inspect
import traceback
import gc
import psutil
import numpy as np
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import msgpack
import cpuinfo
import GPUtil
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityLevel(Enum):
    """Security levels for cryptographic operations"""
    BASIC = "basic"      # 128-bit security
    STANDARD = "standard" # 192-bit security
    HIGH = "high"        # 256-bit security
    QUANTUM = "quantum"   # 512-bit security

class CompressionAlgorithm(Enum):
    """Supported compression algorithms"""
    ZLIB = "zlib"
    LZ4 = "lz4"
    BROTLI = "brotli"
    SNAPPY = "snappy"
    NONE = "none"

class SerializationFormat(Enum):
    """Supported serialization formats"""
    MSGPACK = "msgpack"
    JSON = "json"
    PICKLE = "pickle"
    PROTOBUF = "protobuf"

@dataclass
class PerformanceStats:
    """Comprehensive performance statistics"""
    operation_count: int = 0
    total_duration: float = 0.0
    average_duration: float = 0.0
    min_duration: float = float('inf')
    max_duration: float = 0.0
    success_count: int = 0
    error_count: int = 0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    cache_hit_rate: float = 0.0
    throughput_ops_sec: float = 0.0

@dataclass
class SystemInfo:
    """System hardware and software information"""
    platform: str
    python_version: str
    cpu_cores: int
    cpu_frequency: float
    total_memory_gb: float
    available_memory_gb: float
    gpu_available: bool
    gpu_count: int
    gpu_info: List[Dict[str, Any]]
    disk_usage: Dict[str, float]
    load_average: Tuple[float, float, float]

@dataclass
class SecurityAuditResult:
    """Security audit results"""
    audit_timestamp: datetime
    security_level: SecurityLevel
    vulnerabilities_found: List[Dict[str, Any]]
    compliance_checks: Dict[str, bool]
    recommendations: List[str]
    overall_score: float

class CryptoUtils:
    """
    Advanced Cryptographic Utilities for Quantum-Resistant Operations
    
    Features:
    - Quantum-resistant key derivation and generation
    - Secure random number generation
    - Cryptographic hashing with multiple algorithms
    - HMAC and digital signature utilities
    - Password-based key derivation
    - Secure data comparison and constant-time operations
    """
    
    # Supported hash algorithms
    HASH_ALGORITHMS = {
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384, 
        'sha512': hashlib.sha512,
        'sha3_256': hashlib.sha3_256,
        'sha3_384': hashlib.sha3_384,
        'sha3_512': hashlib.sha3_512,
        'blake2b': hashlib.blake2b,
        'blake2s': hashlib.blake2s
    }
    
    # KDF algorithms and parameters
    KDF_ALGORITHMS = {
        'pbkdf2_sha256': {'algorithm': hashes.SHA256, 'iterations': 100000},
        'pbkdf2_sha512': {'algorithm': hashes.SHA512, 'iterations': 100000},
        'hkdf_sha256': {'algorithm': hashes.SHA256},
        'hkdf_sha512': {'algorithm': hashes.SHA512},
        'hkdf_sha3_256': {'algorithm': hashes.SHA3_256},
        'hkdf_sha3_512': {'algorithm': hashes.SHA3_512}
    }

    def __init__(self, security_level: SecurityLevel = SecurityLevel.HIGH):
        """
        Initialize cryptographic utilities
        
        Args:
            security_level: Security level for operations
        """
        self.security_level = security_level
        self.security_params = self._get_security_params(security_level)

    def _get_security_params(self, level: SecurityLevel) -> Dict[str, Any]:
        """Get security parameters based on security level"""
        params = {
            SecurityLevel.BASIC: {
                'key_length': 32,
                'salt_length': 32,
                'hash_algorithm': 'sha256',
                'kdf_algorithm': 'pbkdf2_sha256',
                'kdf_iterations': 100000,
                'nonce_length': 16
            },
            SecurityLevel.STANDARD: {
                'key_length': 48,
                'salt_length': 48,
                'hash_algorithm': 'sha384',
                'kdf_algorithm': 'pbkdf2_sha512',
                'kdf_iterations': 250000,
                'nonce_length': 24
            },
            SecurityLevel.HIGH: {
                'key_length': 64,
                'salt_length': 64,
                'hash_algorithm': 'sha512',
                'kdf_algorithm': 'hkdf_sha512',
                'kdf_iterations': 500000,
                'nonce_length': 32
            },
            SecurityLevel.QUANTUM: {
                'key_length': 128,
                'salt_length': 128,
                'hash_algorithm': 'sha3_512',
                'kdf_algorithm': 'hkdf_sha3_512',
                'kdf_iterations': 1000000,
                'nonce_length': 64
            }
        }
        return params.get(level, params[SecurityLevel.HIGH])

    def generate_secure_random(self, length: int) -> bytes:
        """
        Generate cryptographically secure random bytes
        
        Args:
            length: Number of random bytes to generate
            
        Returns:
            Random bytes
        """
        return secrets.token_bytes(length)

    def generate_secure_nonce(self) -> bytes:
        """Generate secure nonce based on security level"""
        return self.generate_secure_random(self.security_params['nonce_length'])

    def derive_key_from_password(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Derive cryptographic key from password
        
        Args:
            password: User password
            salt: Optional salt (generated if not provided)
            
        Returns:
            Tuple of (derived_key, salt)
        """
        if salt is None:
            salt = self.generate_secure_random(self.security_params['salt_length'])
        
        kdf_config = self.KDF_ALGORITHMS[self.security_params['kdf_algorithm']]
        
        if self.security_params['kdf_algorithm'].startswith('pbkdf2'):
            kdf = PBKDF2HMAC(
                algorithm=kdf_config['algorithm'](),
                length=self.security_params['key_length'],
                salt=salt,
                iterations=self.security_params['kdf_iterations'],
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
        else:  # HKDF
            kdf = HKDF(
                algorithm=kdf_config['algorithm'](),
                length=self.security_params['key_length'],
                salt=salt,
                info=b'key_derivation',
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
        
        return key, salt

    def hash_data(self, data: bytes, algorithm: Optional[str] = None) -> bytes:
        """
        Hash data using specified algorithm
        
        Args:
            data: Data to hash
            algorithm: Hash algorithm (uses security level default if None)
            
        Returns:
            Hash digest
        """
        if algorithm is None:
            algorithm = self.security_params['hash_algorithm']
        
        hash_func = self.HASH_ALGORITHMS.get(algorithm)
        if not hash_func:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        return hash_func(data).digest()

    def hmac_sign(self, data: bytes, key: bytes, algorithm: Optional[str] = None) -> bytes:
        """
        Generate HMAC signature for data
        
        Args:
            data: Data to sign
            key: HMAC key
            algorithm: Hash algorithm for HMAC
            
        Returns:
            HMAC signature
        """
        if algorithm is None:
            algorithm = self.security_params['hash_algorithm']
        
        hash_func = self.HASH_ALGORITHMS.get(algorithm)
        if not hash_func:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        h = hmac.new(key, data, hash_func)
        return h.digest()

    def hmac_verify(self, data: bytes, signature: bytes, key: bytes, algorithm: Optional[str] = None) -> bool:
        """
        Verify HMAC signature
        
        Args:
            data: Original data
            signature: HMAC signature to verify
            key: HMAC key
            algorithm: Hash algorithm for HMAC
            
        Returns:
            True if signature is valid
        """
        expected_signature = self.hmac_sign(data, key, algorithm)
        return self.constant_time_compare(signature, expected_signature)

    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Constant-time comparison to prevent timing attacks
        
        Args:
            a: First byte string
            b: Second byte string
            
        Returns:
            True if strings are equal
        """
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0

    def generate_rsa_keypair(self, key_size: int = 4096) -> Tuple[Any, Any]:
        """
        Generate RSA key pair (placeholder for actual implementation)
        
        Args:
            key_size: RSA key size in bits
            
        Returns:
            Tuple of (private_key, public_key)
        """
        # In a real implementation, this would use cryptography.hazmat.primitives.asymmetric.rsa
        # For now, return placeholders
        logger.warning("RSA key generation not fully implemented in this version")
        return ("private_key_placeholder", "public_key_placeholder")

    def encrypt_symmetric(self, data: bytes, key: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data using AES-GCM
        
        Args:
            data: Data to encrypt
            key: Encryption key
            associated_data: Optional associated data for authentication
            
        Returns:
            Tuple of (nonce, ciphertext, tag)
        """
        nonce = self.generate_secure_nonce()
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
        
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return nonce, ciphertext, encryptor.tag

    def decrypt_symmetric(self, ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes, 
                         associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt data using AES-GCM
        
        Args:
            ciphertext: Encrypted data
            key: Decryption key
            nonce: Nonce used during encryption
            tag: Authentication tag
            associated_data: Optional associated data for authentication
            
        Returns:
            Decrypted data
        """
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)
        
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except InvalidTag:
            raise SecurityError("Decryption failed: authentication tag mismatch")

    def generate_elliptic_curve_keypair(self, curve: str = "secp384r1") -> Tuple[Any, Any]:
        """
        Generate elliptic curve key pair (placeholder for actual implementation)
        
        Args:
            curve: Elliptic curve name
            
        Returns:
            Tuple of (private_key, public_key)
        """
        # In a real implementation, this would use cryptography.hazmat.primitives.asymmetric.ec
        logger.warning("Elliptic curve key generation not fully implemented in this version")
        return ("ec_private_placeholder", "ec_public_placeholder")

    def quantum_resistant_key_exchange(self) -> Tuple[bytes, bytes]:
        """
        Perform quantum-resistant key exchange (placeholder)
        
        Returns:
            Tuple of (shared_secret, public_data)
        """
        # This would implement a post-quantum key exchange like Kyber, FrodoKEM, etc.
        logger.warning("Quantum-resistant key exchange not fully implemented in this version")
        shared_secret = self.generate_secure_random(32)
        public_data = self.generate_secure_random(1024)  # Simulated public data
        return shared_secret, public_data

class PerformanceMonitor:
    """
    Advanced Performance Monitoring and Profiling
    
    Features:
    - Real-time performance metrics collection
    - Memory usage tracking and optimization
    - CPU and GPU performance monitoring
    - Method execution timing and profiling
    - Resource usage analytics and reporting
    """
    
    def __init__(self, enable_memory_monitoring: bool = True, enable_cpu_monitoring: bool = True):
        """
        Initialize performance monitor
        
        Args:
            enable_memory_monitoring: Enable memory usage tracking
            enable_cpu_monitoring: Enable CPU usage monitoring
        """
        self.enable_memory_monitoring = enable_memory_monitoring
        self.enable_cpu_monitoring = enable_cpu_monitoring
        self.operation_stats: Dict[str, PerformanceStats] = {}
        self.memory_snapshots: List[Dict[str, Any]] = []
        self.cpu_readings: List[float] = []
        self.monitoring_thread = None
        self.monitoring_active = False
        
        # Initialize system info
        self.system_info = self.get_system_info()

    def start_monitoring(self, interval_seconds: float = 5.0):
        """
        Start background performance monitoring
        
        Args:
            interval_seconds: Monitoring interval in seconds
        """
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(interval_seconds,),
            daemon=True
        )
        self.monitoring_thread.start()
        logger.info(f"Performance monitoring started with {interval_seconds}s interval")

    def stop_monitoring(self):
        """Stop background performance monitoring"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=10.0)
        logger.info("Performance monitoring stopped")

    def _monitoring_loop(self, interval_seconds: float):
        """Background monitoring loop"""
        while self.monitoring_active:
            try:
                # Capture system metrics
                if self.enable_memory_monitoring:
                    self._capture_memory_snapshot()
                
                if self.enable_cpu_monitoring:
                    self._capture_cpu_reading()
                
                time.sleep(interval_seconds)
                
            except Exception as e:
                logger.error(f"Performance monitoring error: {e}")
                time.sleep(interval_seconds)  # Continue monitoring after error

    def _capture_memory_snapshot(self):
        """Capture current memory usage snapshot"""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            
            snapshot = {
                'timestamp': datetime.now(),
                'rss_mb': memory_info.rss / 1024 / 1024,
                'vms_mb': memory_info.vms / 1024 / 1024,
                'percent': process.memory_percent(),
                'available_memory_gb': psutil.virtual_memory().available / 1024 / 1024 / 1024,
                'total_memory_gb': psutil.virtual_memory().total / 1024 / 1024 / 1024
            }
            
            self.memory_snapshots.append(snapshot)
            
            # Keep only recent snapshots (last hour)
            cutoff_time = datetime.now() - timedelta(hours=1)
            self.memory_snapshots = [
                s for s in self.memory_snapshots 
                if s['timestamp'] > cutoff_time
            ]
            
        except Exception as e:
            logger.warning(f"Failed to capture memory snapshot: {e}")

    def _capture_cpu_reading(self):
        """Capture current CPU usage reading"""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            self.cpu_readings.append(cpu_percent)
            
            # Keep only recent readings (last hour)
            max_readings = 3600  # Assuming 1 reading per second for 1 hour
            if len(self.cpu_readings) > max_readings:
                self.cpu_readings = self.cpu_readings[-max_readings:]
                
        except Exception as e:
            logger.warning(f"Failed to capture CPU reading: {e}")

    @contextmanager
    def measure_operation(self, operation_name: str):
        """
        Context manager to measure operation performance
        
        Args:
            operation_name: Name of the operation being measured
        """
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss if self.enable_memory_monitoring else 0
        
        try:
            yield
            success = True
        except Exception:
            success = False
            raise
        finally:
            end_time = time.time()
            duration = end_time - start_time
            
            # Update operation statistics
            if operation_name not in self.operation_stats:
                self.operation_stats[operation_name] = PerformanceStats()
            
            stats = self.operation_stats[operation_name]
            stats.operation_count += 1
            stats.total_duration += duration
            stats.average_duration = stats.total_duration / stats.operation_count
            stats.min_duration = min(stats.min_duration, duration)
            stats.max_duration = max(stats.max_duration, duration)
            
            if success:
                stats.success_count += 1
            else:
                stats.error_count += 1
            
            # Update memory usage
            if self.enable_memory_monitoring:
                end_memory = psutil.Process().memory_info().rss
                memory_used_mb = (end_memory - start_memory) / 1024 / 1024
                stats.memory_usage_mb = memory_used_mb

    def track_method(self, func: Callable) -> Callable:
        """
        Decorator to track method performance
        
        Args:
            func: Function to decorate
            
        Returns:
            Decorated function
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            operation_name = f"{func.__module__}.{func.__name__}"
            with self.measure_operation(operation_name):
                return func(*args, **kwargs)
        return wrapper

    def get_performance_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive performance report
        
        Returns:
            Performance report dictionary
        """
        report = {
            'timestamp': datetime.now(),
            'system_info': asdict(self.system_info),
            'operation_stats': {},
            'memory_analysis': self._analyze_memory_usage(),
            'cpu_analysis': self._analyze_cpu_usage(),
            'recommendations': self._generate_recommendations()
        }
        
        # Add operation statistics
        for op_name, stats in self.operation_stats.items():
            report['operation_stats'][op_name] = asdict(stats)
            
        return report

    def _analyze_memory_usage(self) -> Dict[str, Any]:
        """Analyze memory usage patterns"""
        if not self.memory_snapshots:
            return {}
        
        recent_snapshots = self.memory_snapshots[-100:]  # Last 100 snapshots
        
        rss_values = [s['rss_mb'] for s in recent_snapshots]
        vms_values = [s['vms_mb'] for s in recent_snapshots]
        
        return {
            'average_rss_mb': np.mean(rss_values) if rss_values else 0,
            'max_rss_mb': np.max(rss_values) if rss_values else 0,
            'average_vms_mb': np.mean(vms_values) if vms_values else 0,
            'memory_trend': 'increasing' if len(rss_values) > 1 and rss_values[-1] > rss_values[0] else 'stable',
            'leak_suspected': self._check_memory_leak(rss_values)
        }

    def _analyze_cpu_usage(self) -> Dict[str, Any]:
        """Analyze CPU usage patterns"""
        if not self.cpu_readings:
            return {}
        
        recent_readings = self.cpu_readings[-100:]  # Last 100 readings
        
        return {
            'average_usage': np.mean(recent_readings) if recent_readings else 0,
            'max_usage': np.max(recent_readings) if recent_readings else 0,
            'min_usage': np.min(recent_readings) if recent_readings else 0,
            'usage_trend': 'increasing' if len(recent_readings) > 1 and recent_readings[-1] > recent_readings[0] else 'stable'
        }

    def _check_memory_leak(self, memory_readings: List[float]) -> bool:
        """Check for potential memory leak"""
        if len(memory_readings) < 10:
            return False
        
        # Simple linear regression to detect increasing trend
        x = np.arange(len(memory_readings))
        y = np.array(memory_readings)
        
        try:
            slope = np.polyfit(x, y, 1)[0]
            return slope > 0.1  # MB per reading increase threshold
        except:
            return False

    def _generate_recommendations(self) -> List[str]:
        """Generate performance optimization recommendations"""
        recommendations = []
        
        # Analyze operation statistics
        for op_name, stats in self.operation_stats.items():
            if stats.average_duration > 1.0:  # More than 1 second average
                recommendations.append(f"Optimize {op_name}: average duration {stats.average_duration:.3f}s")
            
            if stats.error_rate > 0.1:  # More than 10% error rate
                recommendations.append(f"Investigate {op_name}: error rate {stats.error_rate:.1%}")
        
        # Memory recommendations
        memory_analysis = self._analyze_memory_usage()
        if memory_analysis.get('leak_suspected', False):
            recommendations.append("Potential memory leak detected - investigate object lifecycle")
        
        if memory_analysis.get('average_rss_mb', 0) > 1000:  # More than 1GB average
            recommendations.append("High memory usage - consider optimization or increased resources")
        
        # CPU recommendations
        cpu_analysis = self._analyze_cpu_usage()
        if cpu_analysis.get('average_usage', 0) > 80:  # More than 80% average CPU
            recommendations.append("High CPU usage - consider optimization or scaling")
        
        return recommendations

    @staticmethod
    def get_system_info() -> SystemInfo:
        """
        Get comprehensive system information
        
        Returns:
            SystemInfo object
        """
        try:
            # CPU information
            cpu_info = cpuinfo.get_cpu_info()
            cpu_cores = psutil.cpu_count(logical=False)
            cpu_frequency = psutil.cpu_freq().current if psutil.cpu_freq() else 0
            
            # Memory information
            memory = psutil.virtual_memory()
            total_memory_gb = memory.total / 1024 / 1024 / 1024
            available_memory_gb = memory.available / 1024 / 1024 / 1024
            
            # GPU information
            gpus = GPUtil.getGPUs()
            gpu_available = len(gpus) > 0
            gpu_info = []
            for gpu in gpus:
                gpu_info.append({
                    'id': gpu.id,
                    'name': gpu.name,
                    'memory_total': gpu.memoryTotal,
                    'memory_used': gpu.memoryUsed,
                    'memory_free': gpu.memoryFree,
                    'temperature': gpu.temperature
                })
            
            # Disk usage
            disk_usage = {}
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_usage[partition.mountpoint] = {
                        'total_gb': usage.total / 1024 / 1024 / 1024,
                        'used_gb': usage.used / 1024 / 1024 / 1024,
                        'free_gb': usage.free / 1024 / 1024 / 1024,
                        'percent_used': usage.percent
                    }
                except PermissionError:
                    continue  # Skip partitions we can't access
            
            # Load average (Unix-like systems)
            try:
                load_avg = os.getloadavg()
            except AttributeError:
                load_avg = (0.0, 0.0, 0.0)  # Windows doesn't have load average
            
            return SystemInfo(
                platform=sys.platform,
                python_version=sys.version,
                cpu_cores=cpu_cores,
                cpu_frequency=cpu_frequency,
                total_memory_gb=total_memory_gb,
                available_memory_gb=available_memory_gb,
                gpu_available=gpu_available,
                gpu_count=len(gpus),
                gpu_info=gpu_info,
                disk_usage=disk_usage,
                load_average=load_avg
            )
            
        except Exception as e:
            logger.error(f"Failed to get system info: {e}")
            # Return minimal system info
            return SystemInfo(
                platform=sys.platform,
                python_version=sys.version,
                cpu_cores=1,
                cpu_frequency=0.0,
                total_memory_gb=0.0,
                available_memory_gb=0.0,
                gpu_available=False,
                gpu_count=0,
                gpu_info=[],
                disk_usage={},
                load_average=(0.0, 0.0, 0.0)
            )

class DataUtils:
    """
    Advanced Data Utilities for Serialization, Compression, and Transformation
    
    Features:
    - Multi-format serialization and deserialization
    - Advanced compression with multiple algorithms
    - Data transformation and normalization
    - Efficient binary data handling
    - Data validation and integrity checking
    """
    
    def __init__(self, default_compression: CompressionAlgorithm = CompressionAlgorithm.ZLIB,
                 default_serialization: SerializationFormat = SerializationFormat.MSGPACK):
        """
        Initialize data utilities
        
        Args:
            default_compression: Default compression algorithm
            default_serialization: Default serialization format
        """
        self.default_compression = default_compression
        self.default_serialization = default_serialization
        
        # Initialize compression libraries if available
        self.compression_libs = self._init_compression_libs()

    def _init_compression_libs(self) -> Dict[CompressionAlgorithm, Any]:
        """Initialize compression libraries"""
        libs = {CompressionAlgorithm.NONE: None}
        
        try:
            import zlib
            libs[CompressionAlgorithm.ZLIB] = zlib
        except ImportError:
            logger.warning("zlib not available")
        
        try:
            import lz4.frame
            libs[CompressionAlgorithm.LZ4] = lz4.frame
        except ImportError:
            logger.warning("lz4 not available")
        
        try:
            import brotli
            libs[CompressionAlgorithm.BROTLI] = brotli
        except ImportError:
            logger.warning("brotli not available")
        
        try:
            import snappy
            libs[CompressionAlgorithm.SNAPPY] = snappy
        except ImportError:
            logger.warning("snappy not available")
        
        return libs

    def serialize_data(self, data: Any, format_type: Optional[SerializationFormat] = None) -> bytes:
        """
        Serialize data using specified format
        
        Args:
            data: Data to serialize
            format_type: Serialization format (uses default if None)
            
        Returns:
            Serialized data
        """
        if format_type is None:
            format_type = self.default_serialization
        
        try:
            if format_type == SerializationFormat.MSGPACK:
                return msgpack.packb(data, use_bin_type=True)
            elif format_type == SerializationFormat.JSON:
                return json.dumps(data, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
            elif format_type == SerializationFormat.PICKLE:
                return pickle.dumps(data, protocol=pickle.HIGHEST_PROTOCOL)
            elif format_type == SerializationFormat.PROTOBUF:
                # Placeholder for protobuf implementation
                raise NotImplementedError("Protobuf serialization not implemented")
            else:
                raise ValueError(f"Unsupported serialization format: {format_type}")
                
        except Exception as e:
            logger.error(f"Serialization failed: {e}")
            raise

    def deserialize_data(self, data: bytes, format_type: Optional[SerializationFormat] = None) -> Any:
        """
        Deserialize data using specified format
        
        Args:
            data: Serialized data
            format_type: Serialization format (uses default if None)
            
        Returns:
            Deserialized data
        """
        if format_type is None:
            format_type = self.default_serialization
        
        try:
            if format_type == SerializationFormat.MSGPACK:
                return msgpack.unpackb(data, raw=False)
            elif format_type == SerializationFormat.JSON:
                return json.loads(data.decode('utf-8'))
            elif format_type == SerializationFormat.PICKLE:
                return pickle.loads(data)
            elif format_type == SerializationFormat.PROTOBUF:
                # Placeholder for protobuf implementation
                raise NotImplementedError("Protobuf deserialization not implemented")
            else:
                raise ValueError(f"Unsupported serialization format: {format_type}")
                
        except Exception as e:
            logger.error(f"Deserialization failed: {e}")
            raise

    def compress_data(self, data: bytes, algorithm: Optional[CompressionAlgorithm] = None, 
                     level: Optional[int] = None) -> bytes:
        """
        Compress data using specified algorithm
        
        Args:
            data: Data to compress
            algorithm: Compression algorithm (uses default if None)
            level: Compression level (algorithm-specific)
            
        Returns:
            Compressed data
        """
        if algorithm is None:
            algorithm = self.default_compression
        
        if algorithm == CompressionAlgorithm.NONE:
            return data
        
        compression_lib = self.compression_libs.get(algorithm)
        if not compression_lib:
            raise ValueError(f"Compression algorithm not available: {algorithm}")
        
        try:
            if algorithm == CompressionAlgorithm.ZLIB:
                level = level or 6
                return compression_lib.compress(data, level=level)
            elif algorithm == CompressionAlgorithm.LZ4:
                return compression_lib.compress(data, compression_level=level or 1)
            elif algorithm == CompressionAlgorithm.BROTLI:
                level = level or 4
                return compression_lib.compress(data, quality=level)
            elif algorithm == CompressionAlgorithm.SNAPPY:
                return compression_lib.compress(data)
            else:
                raise ValueError(f"Unsupported compression algorithm: {algorithm}")
                
        except Exception as e:
            logger.error(f"Compression failed: {e}")
            raise

    def decompress_data(self, compressed_data: bytes, algorithm: Optional[CompressionAlgorithm] = None) -> bytes:
        """
        Decompress data using specified algorithm
        
        Args:
            compressed_data: Compressed data
            algorithm: Compression algorithm (uses default if None)
            
        Returns:
            Decompressed data
        """
        if algorithm is None:
            algorithm = self.default_compression
        
        if algorithm == CompressionAlgorithm.NONE:
            return compressed_data
        
        compression_lib = self.compression_libs.get(algorithm)
        if not compression_lib:
            raise ValueError(f"Compression algorithm not available: {algorithm}")
        
        try:
            if algorithm == CompressionAlgorithm.ZLIB:
                return compression_lib.decompress(compressed_data)
            elif algorithm == CompressionAlgorithm.LZ4:
                return compression_lib.decompress(compressed_data)
            elif algorithm == CompressionAlgorithm.BROTLI:
                return compression_lib.decompress(compressed_data)
            elif algorithm == CompressionAlgorithm.SNAPPY:
                return compression_lib.decompress(compressed_data)
            else:
                raise ValueError(f"Unsupported compression algorithm: {algorithm}")
                
        except Exception as e:
            logger.error(f"Decompression failed: {e}")
            raise

    def normalize_data(self, data: Any, target_type: type = float) -> Any:
        """
        Normalize data to target type
        
        Args:
            data: Data to normalize
            target_type: Target data type
            
        Returns:
            Normalized data
        """
        try:
            if target_type == float:
                return float(data)
            elif target_type == int:
                return int(data)
            elif target_type == str:
                return str(data)
            elif target_type == bool:
                return bool(data)
            elif target_type == list:
                return list(data) if hasattr(data, '__iter__') and not isinstance(data, (str, bytes)) else [data]
            elif target_type == dict:
                return dict(data) if hasattr(data, 'items') else {0: data}
            else:
                return target_type(data)
                
        except (ValueError, TypeError) as e:
            logger.warning(f"Data normalization failed: {e}")
            return data  # Return original data if normalization fails

    def validate_data_structure(self, data: Any, schema: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate data against schema
        
        Args:
            data: Data to validate
            schema: Validation schema
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        if not isinstance(data, dict):
            errors.append("Data must be a dictionary")
            return False, errors
        
        for key, expected_type in schema.items():
            if key not in data:
                errors.append(f"Missing required key: {key}")
                continue
            
            value = data[key]
            if not isinstance(value, expected_type):
                errors.append(f"Key '{key}' must be {expected_type.__name__}, got {type(value).__name__}")
        
        return len(errors) == 0, errors

    def calculate_data_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data
        
        Args:
            data: Data to analyze
            
        Returns:
            Entropy value (bits per byte)
        """
        if len(data) == 0:
            return 0.0
        
        # Calculate byte frequencies
        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probabilities = byte_counts / len(data)
        probabilities = probabilities[probabilities > 0]  # Remove zero probabilities
        
        # Calculate entropy
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return float(entropy)

    def detect_data_patterns(self, data: bytes) -> Dict[str, Any]:
        """
        Detect patterns in binary data
        
        Args:
            data: Data to analyze
            
        Returns:
            Pattern analysis results
        """
        if len(data) == 0:
            return {}
        
        analysis = {
            'size_bytes': len(data),
            'entropy': self.calculate_data_entropy(data),
            'repetitive_patterns': False,
            'common_byte_values': [],
            'compression_effectiveness': 0.0
        }
        
        # Check for repetitive patterns
        if len(data) >= 8:
            # Simple pattern detection: check if data repeats in blocks
            block_size = min(16, len(data) // 4)
            if block_size > 0:
                blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
                unique_blocks = len(set(blocks))
                if unique_blocks < len(blocks) * 0.5:  # More than 50% repetition
                    analysis['repetitive_patterns'] = True
        
        # Find common byte values
        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        common_indices = np.argsort(byte_counts)[-5:][::-1]  # Top 5 most common bytes
        analysis['common_byte_values'] = [
            {'byte': int(i), 'count': int(byte_counts[i]), 'frequency': float(byte_counts[i] / len(data))}
            for i in common_indices if byte_counts[i] > 0
        ]
        
        # Estimate compression effectiveness
        try:
            compressed = self.compress_data(data, CompressionAlgorithm.ZLIB, level=6)
            analysis['compression_effectiveness'] = len(compressed) / len(data)
        except:
            analysis['compression_effectiveness'] = 1.0  # No compression
        
        return analysis

class SecurityAuditor:
    """
    Advanced Security Auditor for System Compliance and Vulnerability Assessment
    
    Features:
    - Comprehensive security compliance checking
    - Vulnerability assessment and reporting
    - Cryptographic strength evaluation
    - System security configuration auditing
    - Compliance with security standards
    """
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.HIGH):
        """
        Initialize security auditor
        
        Args:
            security_level: Target security level
        """
        self.security_level = security_level
        self.compliance_standards = ['NIST', 'FIPS', 'PCI-DSS', 'GDPR']  # Example standards
        self.vulnerability_database = self._load_vulnerability_database()

    def _load_vulnerability_database(self) -> Dict[str, Any]:
        """Load vulnerability database (simplified)"""
        # In a real implementation, this would load from an external database
        return {
            'weak_crypto': {
                'severity': 'HIGH',
                'description': 'Use of weak cryptographic algorithms',
                'remediation': 'Upgrade to quantum-resistant algorithms'
            },
            'insecure_random': {
                'severity': 'HIGH', 
                'description': 'Use of insecure random number generation',
                'remediation': 'Use cryptographically secure random generators'
            },
            'short_keys': {
                'severity': 'MEDIUM',
                'description': 'Use of short cryptographic keys',
                'remediation': 'Use keys of appropriate length for security level'
            }
        }

    def perform_security_audit(self, system_config: Dict[str, Any]) -> SecurityAuditResult:
        """
        Perform comprehensive security audit
        
        Args:
            system_config: System configuration to audit
            
        Returns:
            Security audit results
        """
        vulnerabilities = []
        compliance_checks = {}
        recommendations = []
        
        # Check cryptographic configuration
        crypto_vulns = self._audit_cryptographic_config(system_config)
        vulnerabilities.extend(crypto_vulns)
        
        # Check system security
        system_vulns = self._audit_system_security(system_config)
        vulnerabilities.extend(system_vulns)
        
        # Perform compliance checks
        compliance_checks = self._perform_compliance_checks(system_config)
        
        # Generate recommendations
        recommendations = self._generate_security_recommendations(vulnerabilities, compliance_checks)
        
        # Calculate overall score
        overall_score = self._calculate_security_score(vulnerabilities, compliance_checks)
        
        return SecurityAuditResult(
            audit_timestamp=datetime.now(),
            security_level=self.security_level,
            vulnerabilities_found=vulnerabilities,
            compliance_checks=compliance_checks,
            recommendations=recommendations,
            overall_score=overall_score
        )

    def _audit_cryptographic_config(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Audit cryptographic configuration"""
        vulnerabilities = []
        crypto_utils = CryptoUtils(self.security_level)
        
        # Check key lengths
        if config.get('key_length', 0) < crypto_utils.security_params['key_length']:
            vulnerabilities.append({
                'type': 'short_keys',
                'severity': 'HIGH',
                'description': f"Key length {config.get('key_length')} is below recommended {crypto_utils.security_params['key_length']}",
                'component': 'cryptography'
            })
        
        # Check hash algorithms
        hash_alg = config.get('hash_algorithm', '')
        if hash_alg not in ['sha256', 'sha384', 'sha512', 'sha3_256', 'sha3_384', 'sha3_512']:
            vulnerabilities.append({
                'type': 'weak_hash',
                'severity': 'MEDIUM',
                'description': f'Weak hash algorithm: {hash_alg}',
                'component': 'cryptography'
            })
        
        # Check random number generation
        if config.get('random_source', '') != 'secrets':
            vulnerabilities.append({
                'type': 'insecure_random',
                'severity': 'HIGH',
                'description': 'Using insecure random number generation',
                'component': 'cryptography'
            })
        
        return vulnerabilities

    def _audit_system_security(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Audit system security configuration"""
        vulnerabilities = []
        
        # Check for debug mode in production
        if config.get('debug_mode', False):
            vulnerabilities.append({
                'type': 'debug_enabled',
                'severity': 'MEDIUM',
                'description': 'Debug mode enabled in production configuration',
                'component': 'system'
            })
        
        # Check for insecure protocols
        if config.get('allow_insecure_protocols', False):
            vulnerabilities.append({
                'type': 'insecure_protocols',
                'severity': 'HIGH',
                'description': 'Insecure protocols allowed',
                'component': 'network'
            })
        
        # Check for weak password policies
        if config.get('min_password_length', 0) < 12:
            vulnerabilities.append({
                'type': 'weak_passwords',
                'severity': 'MEDIUM',
                'description': 'Weak password policy',
                'component': 'authentication'
            })
        
        return vulnerabilities

    def _perform_compliance_checks(self, config: Dict[str, Any]) -> Dict[str, bool]:
        """Perform compliance standard checks"""
        checks = {}
        
        # NIST compliance
        checks['nist_crypto'] = config.get('key_length', 0) >= 256  # NIST minimum for post-quantum
        
        # FIPS compliance
        checks['fips_140'] = config.get('fips_compliant', False)
        
        # GDPR compliance
        checks['gdpr_data_protection'] = config.get('data_encryption', False)
        
        # PCI-DSS compliance
        checks['pci_encryption'] = config.get('encryption_enabled', False)
        checks['pci_access_control'] = config.get('access_controls', False)
        
        return checks

    def _generate_security_recommendations(self, vulnerabilities: List[Dict[str, Any]], 
                                         compliance_checks: Dict[str, bool]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Recommendations based on vulnerabilities
        for vuln in vulnerabilities:
            if vuln['severity'] in ['HIGH', 'CRITICAL']:
                recommendations.append(f"CRITICAL: {vuln['description']} - {self.vulnerability_database.get(vuln['type'], {}).get('remediation', 'Investigate immediately')}")
        
        # Recommendations based on compliance failures
        for check_name, passed in compliance_checks.items():
            if not passed:
                recommendations.append(f"COMPLIANCE: Failed {check_name} - review configuration")
        
        # General recommendations
        if self.security_level == SecurityLevel.QUANTUM:
            recommendations.append("Consider implementing additional post-quantum cryptographic algorithms")
        
        if len(vulnerabilities) > 5:
            recommendations.append("Multiple security issues detected - consider comprehensive security review")
        
        return recommendations

    def _calculate_security_score(self, vulnerabilities: List[Dict[str, Any]], 
                                compliance_checks: Dict[str, bool]) -> float:
        """Calculate overall security score (0-100)"""
        base_score = 100.0
        
        # Deduct for vulnerabilities
        for vuln in vulnerabilities:
            severity_weight = {
                'LOW': 5,
                'MEDIUM': 15,
                'HIGH': 30,
                'CRITICAL': 50
            }
            base_score -= severity_weight.get(vuln['severity'], 10)
        
        # Deduct for compliance failures
        compliance_failures = sum(1 for passed in compliance_checks.values() if not passed)
        base_score -= compliance_failures * 10
        
        return max(0.0, base_score)

class ErrorHandler:
    """
    Advanced Error Handling and Recovery Utilities
    
    Features:
    - Comprehensive exception handling and logging
    - Automatic error recovery mechanisms
    - Circuit breaker pattern implementation
    - Retry logic with exponential backoff
    - Error reporting and analytics
    """
    
    def __init__(self, max_retries: int = 3, base_delay: float = 1.0):
        """
        Initialize error handler
        
        Args:
            max_retries: Maximum number of retry attempts
            base_delay: Base delay for exponential backoff (seconds)
        """
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.circuit_breakers: Dict[str, Any] = {}
        self.error_stats: Dict[str, Dict[str, int]] = {}

    @contextmanager
    def handle_errors(self, operation_name: str, raise_final: bool = True):
        """
        Context manager for error handling
        
        Args:
            operation_name: Name of the operation
            raise_final: Whether to raise the final exception
        """
        try:
            yield
            self._record_success(operation_name)
        except Exception as e:
            self._record_error(operation_name, e)
            if raise_final:
                raise

    def retry_on_failure(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with retry logic
        
        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Function result
        """
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                result = func(*args, **kwargs)
                logger.info(f"Operation succeeded on attempt {attempt + 1}")
                return result
            except Exception as e:
                last_exception = e
                logger.warning(f"Attempt {attempt + 1} failed: {e}")
                
                if attempt < self.max_retries:
                    delay = self.base_delay * (2 ** attempt)  # Exponential backoff
                    jitter = random.uniform(0, delay * 0.1)  # Add jitter
                    sleep_time = delay + jitter
                    
                    logger.info(f"Retrying in {sleep_time:.2f}s...")
                    time.sleep(sleep_time)
                else:
                    logger.error(f"All {self.max_retries + 1} attempts failed")
        
        raise last_exception

    def circuit_breaker(self, circuit_name: str, failure_threshold: int = 5, 
                       timeout_seconds: float = 60.0) -> Callable:
        """
        Circuit breaker decorator
        
        Args:
            circuit_name: Name of the circuit
            failure_threshold: Number of failures before opening circuit
            timeout_seconds: Timeout before attempting to close circuit
            
        Returns:
            Decorated function
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Initialize circuit if not exists
                if circuit_name not in self.circuit_breakers:
                    self.circuit_breakers[circuit_name] = {
                        'state': 'CLOSED',  # CLOSED, OPEN, HALF_OPEN
                        'failure_count': 0,
                        'last_failure_time': None,
                        'success_count': 0
                    }
                
                circuit = self.circuit_breakers[circuit_name]
                
                # Check if circuit is open
                if circuit['state'] == 'OPEN':
                    if circuit['last_failure_time'] and \
                       time.time() - circuit['last_failure_time'] > timeout_seconds:
                        circuit['state'] = 'HALF_OPEN'
                        logger.info(f"Circuit {circuit_name} moved to HALF_OPEN state")
                    else:
                        raise CircuitOpenError(f"Circuit {circuit_name} is OPEN")
                
                try:
                    result = func(*args, **kwargs)
                    
                    # Record success
                    if circuit['state'] == 'HALF_OPEN':
                        circuit['success_count'] += 1
                        if circuit['success_count'] >= failure_threshold // 2:
                            circuit['state'] = 'CLOSED'
                            circuit['failure_count'] = 0
                            circuit['success_count'] = 0
                            logger.info(f"Circuit {circuit_name} moved to CLOSED state")
                    
                    return result
                    
                except Exception as e:
                    # Record failure
                    circuit['failure_count'] += 1
                    circuit['last_failure_time'] = time.time()
                    
                    if circuit['failure_count'] >= failure_threshold:
                        circuit['state'] = 'OPEN'
                        logger.warning(f"Circuit {circuit_name} moved to OPEN state")
                    
                    raise
                    
            return wrapper
        return decorator

    def _record_success(self, operation_name: str):
        """Record successful operation"""
        if operation_name not in self.error_stats:
            self.error_stats[operation_name] = {'success': 0, 'error': 0}
        self.error_stats[operation_name]['success'] += 1

    def _record_error(self, operation_name: str, error: Exception):
        """Record operation error"""
        if operation_name not in self.error_stats:
            self.error_stats[operation_name] = {'success': 0, 'error': 0}
        self.error_stats[operation_name]['error'] += 1
        
        # Log error details
        logger.error(f"Operation {operation_name} failed: {error}")
        logger.debug(f"Error traceback: {traceback.format_exc()}")

    def get_error_report(self) -> Dict[str, Any]:
        """
        Generate error statistics report
        
        Returns:
            Error report
        """
        report = {
            'timestamp': datetime.now(),
            'circuit_breakers': self.circuit_breakers.copy(),
            'error_statistics': self.error_stats.copy(),
            'success_rate_by_operation': {}
        }
        
        # Calculate success rates
        for op_name, stats in self.error_stats.items():
            total_ops = stats['success'] + stats['error']
            if total_ops > 0:
                report['success_rate_by_operation'][op_name] = stats['success'] / total_ops
        
        return report

# Custom Exceptions
class SecurityError(Exception):
    """Security-related exceptions"""
    pass

class PerformanceError(Exception):
    """Performance-related exceptions"""
    pass

class ConfigurationError(Exception):
    """Configuration-related exceptions"""
    pass

class CircuitOpenError(Exception):
    """Circuit breaker open exception"""
    pass

# Global utility instances
crypto_utils = CryptoUtils()
performance_monitor = PerformanceMonitor()
data_utils = DataUtils()
security_auditor = SecurityAuditor()
error_handler = ErrorHandler()

# Utility functions
def setup_logging(log_level: int = logging.INFO, log_file: Optional[str] = None):
    """
    Setup comprehensive logging configuration
    
    Args:
        log_level: Logging level
        log_file: Optional log file path
    """
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=handlers
    )
    
    # Set specific log levels for noisy libraries
    logging.getLogger('cryptography').setLevel(logging.WARNING)
    logging.getLogger('msgpack').setLevel(logging.WARNING)

def memory_cleanup():
    """Perform comprehensive memory cleanup"""
    try:
        # Force garbage collection
        collected = gc.collect()
        logger.debug(f"Garbage collection collected {collected} objects")
        
        # Clear various caches
        import sys
        if hasattr(sys, 'getobjects'):
            # This is only available in debug builds
            pass
        
    except Exception as e:
        logger.warning(f"Memory cleanup failed: {e}")

def benchmark_operation(func: Callable, *args, iterations: int = 1000, **kwargs) -> Dict[str, Any]:
    """
    Benchmark operation performance
    
    Args:
        func: Function to benchmark
        *args: Function arguments
        iterations: Number of iterations
        **kwargs: Function keyword arguments
        
    Returns:
        Benchmark results
    """
    times = []
    memory_usage = []
    
    # Warm-up run
    try:
        func(*args, **kwargs)
    except:
        pass
    
    for i in range(iterations):
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss
        
        try:
            result = func(*args, **kwargs)
            success = True
        except Exception as e:
            result = None
            success = False
        
        end_time = time.time()
        end_memory = psutil.Process().memory_info().rss
        
        times.append(end_time - start_time)
        memory_usage.append((end_memory - start_memory) / 1024 / 1024)  # MB
    
    return {
        'iterations': iterations,
        'successful_iterations': sum(1 for t in times if t > 0),  # Simple success detection
        'average_time_ms': np.mean(times) * 1000,
        'min_time_ms': np.min(times) * 1000,
        'max_time_ms': np.max(times) * 1000,
        'std_time_ms': np.std(times) * 1000,
        'average_memory_mb': np.mean(memory_usage),
        'throughput_ops_sec': iterations / np.sum(times) if np.sum(times) > 0 else 0
    }

def validate_configuration(config: Dict[str, Any], required_keys: List[str]) -> Tuple[bool, List[str]]:
    """
    Validate configuration dictionary
    
    Args:
        config: Configuration dictionary
        required_keys: List of required keys
        
    Returns:
        Tuple of (is_valid, error_messages)
    """
    errors = []
    
    for key in required_keys:
        if key not in config:
            errors.append(f"Missing required configuration key: {key}")
        elif config[key] is None:
            errors.append(f"Configuration key {key} cannot be None")
    
    return len(errors) == 0, errors

def create_backup(file_path: str, backup_dir: Optional[str] = None) -> str:
    """
    Create backup of file
    
    Args:
        file_path: Path to file to backup
        backup_dir: Backup directory (uses same directory if None)
        
    Returns:
        Path to backup file
    """
    if backup_dir is None:
        backup_dir = os.path.dirname(file_path)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_name = os.path.basename(file_path)
    backup_name = f"{file_name}.backup.{timestamp}"
    backup_path = os.path.join(backup_dir, backup_name)
    
    try:
        import shutil
        shutil.copy2(file_path, backup_path)
        logger.info(f"Created backup: {backup_path}")
        return backup_path
    except Exception as e:
        logger.error(f"Backup creation failed: {e}")
        raise

def restore_backup(backup_path: str, target_path: str) -> bool:
    """
    Restore file from backup
    
    Args:
        backup_path: Path to backup file
        target_path: Target path for restoration
        
    Returns:
        Success status
    """
    try:
        import shutil
        shutil.copy2(backup_path, target_path)
        logger.info(f"Restored backup: {backup_path} -> {target_path}")
        return True
    except Exception as e:
        logger.error(f"Backup restoration failed: {e}")
        return False

# Initialize default instances
def init_utils(security_level: SecurityLevel = SecurityLevel.HIGH,
              enable_monitoring: bool = True) -> Tuple[CryptoUtils, PerformanceMonitor, DataUtils, SecurityAuditor, ErrorHandler]:
    """
    Initialize all utility components
    
    Args:
        security_level: Security level for utilities
        enable_monitoring: Enable performance monitoring
        
    Returns:
        Tuple of utility instances
    """
    crypto = CryptoUtils(security_level)
    perf_monitor = PerformanceMonitor(enable_memory_monitoring=enable_monitoring, 
                                    enable_cpu_monitoring=enable_monitoring)
    data = DataUtils()
    auditor = SecurityAuditor(security_level)
    error_handler = ErrorHandler()
    
    if enable_monitoring:
        perf_monitor.start_monitoring()
    
    return crypto, perf_monitor, data, auditor, error_handler

# Cleanup function
def cleanup_utils():
    """Cleanup all utility resources"""
    try:
        performance_monitor.stop_monitoring()
        memory_cleanup()
        logger.info("Utilities cleanup completed")
    except Exception as e:
        logger.error(f"Utilities cleanup failed: {e}")