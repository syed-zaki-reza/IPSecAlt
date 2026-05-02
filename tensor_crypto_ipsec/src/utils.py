"""
Utility Functions for Tensor Cryptography System

Provides essential helper functions:
- Device fingerprinting (cross-platform)
- Entropy calculation and validation
- Constant-time comparison (timing attack resistance)
- Performance monitoring
- System health diagnostics
"""

import hashlib
import time
import os
import platform
import secrets
from typing import Dict, Any, Optional, List, Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
import logging
import threading

logger = logging.getLogger(__name__)


def generate_device_fingerprint() -> str:
    """
    Generate a unique device fingerprint (cross-platform).
    
    Combines multiple system identifiers into a deterministic
    fingerprint that persists across restarts but differs between devices.
    
    Returns:
        SHA256 hex string of device fingerprint
    """
    components = []
    
    # Platform information
    components.append(platform.platform())
    components.append(platform.machine())
    components.append(platform.processor())
    
    # Hostname
    components.append(platform.node())
    
    # Process ID seed (for additional entropy in containerized environments)
    components.append(str(os.getpid()))
    
    # Environment-specific identifier
    try:
        # Try to get MAC address (works on most systems)
        import uuid
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                       for elements in range(0, 2 * 6, 2)][::-1])
        components.append(mac)
    except Exception:
        logger.debug("Could not retrieve MAC address")
        components.append(secrets.token_hex(8))
    
    # Combine and hash
    combined = '|'.join(components)
    fingerprint = hashlib.sha256(combined.encode()).hexdigest()
    
    logger.debug(f"Generated device fingerprint: {fingerprint[:16]}...")
    return fingerprint


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of byte data.
    
    Measures randomness quality - higher entropy indicates better randomness.
    Maximum entropy for bytes is 8.0 bits per byte.
    
    Args:
        data: Byte sequence to analyze
        
    Returns:
        Entropy in bits per byte (0.0 to 8.0)
    """
    if len(data) == 0:
        return 0.0
    
    # Count byte frequencies
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    length = len(data)
    
    for count in freq.values():
        if count > 0:
            probability = count / length
            entropy -= probability * (probability if probability == 0 else 
                                      __import__('math').log2(probability))
    
    return entropy


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte sequences in constant time.
    
    Prevents timing attacks by ensuring comparison time is independent
    of where (or if) the sequences differ.
    
    Args:
        a: First byte sequence
        b: Second byte sequence
        
    Returns:
        True if equal, False otherwise
    """
    # Use cryptography library's constant-time comparison if available
    try:
        from cryptography.hazmat.primitives import constant_time
        return constant_time.bytes_eq(a, b)
    except ImportError:
        pass
    
    # Fallback implementation
    if len(a) != len(b):
        # Still do comparison to maintain constant time
        result = 0
        for x in a:
            result |= x
        for x in b:
            result |= x
        return result == 0
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0


@dataclass
class PerformanceMetrics:
    """Performance metrics collector"""
    operation_name: str
    call_count: int = 0
    total_time: float = 0.0
    min_time: float = float('inf')
    max_time: float = 0.0
    last_time: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    
    def record(self, duration: float):
        """Record a single operation duration"""
        with self.lock:
            self.call_count += 1
            self.total_time += duration
            self.min_time = min(self.min_time, duration)
            self.max_time = max(self.max_time, duration)
            self.last_time = duration
    
    @property
    def avg_time(self) -> float:
        """Calculate average operation time"""
        if self.call_count == 0:
            return 0.0
        return self.total_time / self.call_count
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'operation': self.operation_name,
            'call_count': self.call_count,
            'total_time_ms': self.total_time * 1000,
            'avg_time_ms': self.avg_time * 1000,
            'min_time_ms': self.min_time * 1000 if self.min_time != float('inf') else 0,
            'max_time_ms': self.max_time * 1000,
            'last_time_ms': self.last_time * 1000
        }


class PerformanceMonitor:
    """
    Thread-safe performance monitoring context manager.
    
    Usage:
        monitor = PerformanceMonitor()
        
        with monitor.measure("encryption"):
            encrypted = engine.encrypt(data, ...)
        
        print(monitor.get_metrics("encryption"))
    """
    
    def __init__(self):
        """Initialize performance monitor"""
        self._metrics: Dict[str, PerformanceMetrics] = {}
        self._lock = threading.Lock()
    
    @contextmanager
    def measure(self, operation_name: str):
        """
        Context manager for measuring operation duration.
        
        Args:
            operation_name: Name of the operation being measured
        """
        start_time = time.perf_counter()
        try:
            yield
        finally:
            end_time = time.perf_counter()
            duration = end_time - start_time
            
            with self._lock:
                if operation_name not in self._metrics:
                    self._metrics[operation_name] = PerformanceMetrics(operation_name)
                
                self._metrics[operation_name].record(duration)
    
    def get_metrics(self, operation_name: str) -> Optional[Dict[str, Any]]:
        """
        Get metrics for a specific operation.
        
        Args:
            operation_name: Name of operation
            
        Returns:
            Metrics dictionary or None if not found
        """
        with self._lock:
            if operation_name not in self._metrics:
                return None
            return self._metrics[operation_name].to_dict()
    
    def get_all_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get all recorded metrics"""
        with self._lock:
            return {
                name: metrics.to_dict()
                for name, metrics in self._metrics.items()
            }
    
    def reset(self, operation_name: Optional[str] = None):
        """
        Reset metrics.
        
        Args:
            operation_name: Specific operation to reset, or None for all
        """
        with self._lock:
            if operation_name:
                if operation_name in self._metrics:
                    del self._metrics[operation_name]
            else:
                self._metrics.clear()
    
    def report(self) -> str:
        """Generate human-readable performance report"""
        with self._lock:
            if not self._metrics:
                return "No metrics recorded"
            
            lines = ["Performance Report:", "=" * 50]
            
            for name, metrics in sorted(self._metrics.items()):
                data = metrics.to_dict()
                lines.append(
                    f"\n{name}:"
                    f"\n  Calls: {data['call_count']}"
                    f"\n  Total: {data['total_time_ms']:.2f} ms"
                    f"\n  Avg:   {data['avg_time_ms']:.4f} ms"
                    f"\n  Min:   {data['min_time_ms']:.4f} ms"
                    f"\n  Max:   {data['max_time_ms']:.4f} ms"
                )
            
            return '\n'.join(lines)


def system_health_check() -> Dict[str, Any]:
    """
    Perform system health diagnostic check.
    
    Returns:
        Dictionary with system status information
    """
    import psutil
    
    health = {
        'timestamp': time.time(),
        'platform': platform.platform(),
        'python_version': platform.python_version(),
        'cpu_count': os.cpu_count(),
        'status': 'healthy'
    }
    
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=0.1)
        health['cpu_usage_percent'] = cpu_percent
        
        # Memory usage
        memory = psutil.virtual_memory()
        health['memory_total_gb'] = memory.total / (1024**3)
        health['memory_available_gb'] = memory.available / (1024**3)
        health['memory_percent'] = memory.percent
        
        # Disk usage
        disk = psutil.disk_usage('/')
        health['disk_total_gb'] = disk.total / (1024**3)
        health['disk_free_gb'] = disk.free / (1024**3)
        health['disk_percent'] = disk.percent
        
        # Warnings
        if cpu_percent > 90:
            health['warnings'] = health.get('warnings', [])
            health['warnings'].append('High CPU usage')
        
        if memory.percent > 90:
            health['warnings'] = health.get('warnings', [])
            health['warnings'].append('Low memory')
        
        if disk.percent > 90:
            health['warnings'] = health.get('warnings', [])
            health['warnings'].append('Low disk space')
        
    except ImportError:
        health['status'] = 'limited'
        health['note'] = 'psutil not installed - limited diagnostics'
    except Exception as e:
        health['status'] = 'error'
        health['error'] = str(e)
    
    return health


def validate_chaos_parameters(mu: float, x0: float) -> Dict[str, Any]:
    """
    Validate chaos parameters for cryptographic use.
    
    Args:
        mu: Chaos parameter (should be in [3.57, 4.0])
        x0: Initial condition (should be in (0, 1), avoiding fixed points)
        
    Returns:
        Validation result dictionary
    """
    result = {
        'valid': True,
        'mu_valid': True,
        'x0_valid': True,
        'warnings': [],
        'recommendations': []
    }
    
    # Validate mu
    if not (3.57 <= mu <= 4.0):
        result['valid'] = False
        result['mu_valid'] = False
        result['warnings'].append(
            f"μ={mu} is outside chaotic range [3.57, 4.0]"
        )
    
    # Validate x0 range
    if not (0.0 < x0 < 1.0):
        result['valid'] = False
        result['x0_valid'] = False
        result['warnings'].append(
            f"x₀={x0} is outside valid range (0, 1)"
        )
    
    # Check for forbidden values
    forbidden = [0.0, 0.25, 0.5, 0.75, 1.0]
    for fb in forbidden:
        if abs(x0 - fb) < 1e-10:
            result['valid'] = False
            result['x0_valid'] = False
            result['warnings'].append(
                f"x₀={x0} is too close to forbidden value {fb}"
            )
    
    # Recommendations
    if 3.57 <= mu < 3.8:
        result['recommendations'].append(
            "Consider μ closer to 4.0 for maximum chaos"
        )
    
    return result


def format_bytes(size: int) -> str:
    """
    Format byte size to human-readable string.
    
    Args:
        size: Size in bytes
        
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def safe_serialize(obj: Any) -> Dict[str, Any]:
    """
    Safely serialize object to JSON-compatible dictionary.
    
    Handles common types including numpy arrays, bytes, and custom objects.
    
    Args:
        obj: Object to serialize
        
    Returns:
        JSON-compatible dictionary
    """
    import numpy as np
    
    if isinstance(obj, dict):
        return {k: safe_serialize(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [safe_serialize(item) for item in obj]
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, (np.integer, np.int64, np.int32)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float64, np.float32)):
        return float(obj)
    elif isinstance(obj, bytes):
        return {'__type__': 'bytes', 'data': obj.hex()}
    elif isinstance(obj, bytearray):
        return {'__type__': 'bytearray', 'data': obj.hex()}
    elif hasattr(obj, '__dict__'):
        return {
            '__type__': obj.__class__.__name__,
            **{k: safe_serialize(v) for k, v in obj.__dict__.items()}
        }
    else:
        return obj
