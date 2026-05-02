"""
Chaos Engine - Mathematical Foundation for Chaotic Tensor Mappings

Implements the Logistic Map and chaotic sequence generation for quantum-resistant
cryptographic operations. This is the core mathematical foundation of the system.

Core Equation: x_{n+1} = μ * x_n * (1 - x_n)

Features:
- Logistic Map-based chaotic sequence generation
- 64-bit float precision for maximum entropy
- Deterministic recreation via Mirror Chaos Engine
- Session-specific seed validation
"""

import numpy as np
import hashlib
import secrets
from typing import Tuple, List, Optional, Dict
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class ChaosParameters:
    """Parameters for chaotic map generation"""
    mu: float  # Chaos factor (must be in [3.57, 4.0] for chaotic behavior)
    x0: float  # Initial condition
    iterations: int  # Number of iterations
    precision: int = 64  # Float precision in bits
    
    def validate(self) -> bool:
        """Validate parameters for chaotic behavior"""
        # μ must be in chaotic range [3.57, 4.0]
        if not (3.57 <= self.mu <= 4.0):
            return False
        
        # x₀ must avoid fixed points
        forbidden = {0.0, 0.25, 0.5, 0.75, 1.0}
        if self.x0 in forbidden:
            return False
        
        # x₀ must be in valid range (0, 1)
        if not (0.0 < self.x0 < 1.0):
            return False
        
        return True


class ChaosEngine:
    """
    Chaos Engine for generating deterministic chaotic sequences.
    
    The engine uses the Logistic Map to generate pseudo-random sequences
    that are deterministic given the same initial conditions (x₀, μ).
    This enables the "Mirror Chaos Engine" concept where receivers can
    recreate exact permutation indices without transmission.
    
    Attributes:
        params: ChaosParameters instance with μ, x₀, and iteration count
        sequence: Generated chaotic sequence (cached)
        tensor_shape: Target 3D tensor shape (default: 8×8×8)
    """
    
    FORBIDDEN_X0_VALUES = frozenset([0.0, 0.25, 0.5, 0.75, 1.0])
    DEFAULT_TENSOR_SHAPE = (8, 8, 8)  # 512 bytes per block
    MIN_ITERATIONS = 100
    MAX_ITERATIONS = 100000
    
    def __init__(
        self,
        mu: Optional[float] = None,
        x0: Optional[float] = None,
        iterations: int = 512,
        tensor_shape: Tuple[int, int, int] = DEFAULT_TENSOR_SHAPE
    ):
        """
        Initialize the Chaos Engine.
        
        Args:
            mu: Chaos factor (default: 4.0 for maximum chaos)
            x0: Initial condition (default: cryptographically random)
            iterations: Number of iterations (default: 512 for 8×8×8 tensor)
            tensor_shape: Target 3D tensor dimensions
        """
        self.tensor_shape = tensor_shape
        self._sequence_cache: Dict[str, np.ndarray] = {}
        
        # Set default values if not provided
        if mu is None:
            mu = 4.0  # Maximum chaos
        
        if x0 is None:
            x0 = self._generate_secure_x0()
        
        # Validate and set parameters
        self.params = ChaosParameters(
            mu=float(mu),
            x0=float(x0),
            iterations=max(iterations, self.MIN_ITERATIONS)
        )
        
        if not self.params.validate():
            raise ValueError(
                f"Invalid chaos parameters: mu={mu}, x0={x0}. "
                f"Must have mu∈[3.57, 4.0] and x0∈(0,1)\\{self.FORBIDDEN_X0_VALUES}"
            )
        
        self.sequence: Optional[np.ndarray] = None
    
    def _generate_secure_x0(self) -> float:
        """
        Generate a cryptographically secure initial condition x₀.
        
        Uses OS-level CSPRNG to ensure x₀ is never a forbidden value
        and has maximum entropy.
        
        Returns:
            float: Random value in (0, 1) excluding forbidden values
        """
        while True:
            # Generate random bytes and convert to float in (0, 1)
            random_bytes = secrets.token_bytes(8)
            random_int = int.from_bytes(random_bytes, byteorder='big')
            x0 = random_int / (2**64)
            
            # Ensure x0 is not 0 or 1
            if x0 == 0.0:
                x0 = 1e-10
            elif x0 == 1.0:
                x0 = 1.0 - 1e-10
            
            # Check against forbidden values with tolerance
            is_forbidden = any(
                abs(x0 - forbidden) < 1e-10 
                for forbidden in self.FORBIDDEN_X0_VALUES
            )
            
            if not is_forbidden:
                return x0
    
    @staticmethod
    def logistic_map(x: float, mu: float) -> float:
        """
        Compute one iteration of the Logistic Map.
        
        Formula: x_{n+1} = μ * x_n * (1 - x_n)
        
        Args:
            x: Current value x_n
            mu: Chaos parameter μ
            
        Returns:
            float: Next value x_{n+1}
        """
        return mu * x * (1.0 - x)
    
    def generate_sequence(
        self,
        mu: Optional[float] = None,
        x0: Optional[float] = None,
        iterations: Optional[int] = None,
        cache_key: Optional[str] = None
    ) -> np.ndarray:
        """
        Generate a chaotic sequence using the Logistic Map.
        
        Args:
            mu: Chaos factor (uses instance default if None)
            x0: Initial condition (uses instance default if None)
            iterations: Number of iterations (uses instance default if None)
            cache_key: Optional key to cache the sequence
            
        Returns:
            np.ndarray: Array of chaotic values in (0, 1)
        """
        # Use instance defaults if not specified
        mu = mu if mu is not None else self.params.mu
        x0 = x0 if x0 is not None else self.params.x0
        iterations = iterations if iterations is not None else self.params.iterations
        
        # Check cache
        if cache_key and cache_key in self._sequence_cache:
            logger.debug(f"Cache hit for key: {cache_key}")
            return self._sequence_cache[cache_key].copy()
        
        # Validate parameters
        if not (3.57 <= mu <= 4.0):
            raise ValueError(f"μ must be in [3.57, 4.0], got {mu}")
        if not (0.0 < x0 < 1.0):
            raise ValueError(f"x₀ must be in (0, 1), got {x0}")
        
        # Generate sequence
        sequence = np.zeros(iterations, dtype=np.float64)
        x = x0
        
        # Skip transient iterations (burn-in period)
        burn_in = min(100, iterations // 10)
        for _ in range(burn_in):
            x = self.logistic_map(x, mu)
        
        # Collect actual sequence
        for i in range(iterations):
            x = self.logistic_map(x, mu)
            sequence[i] = x
        
        # Cache if requested
        if cache_key:
            self._sequence_cache[cache_key] = sequence.copy()
        
        return sequence
    
    def generate_tensor(
        self,
        mu: Optional[float] = None,
        x0: Optional[float] = None,
        shape: Optional[Tuple[int, int, int]] = None,
        cache_key: Optional[str] = None
    ) -> np.ndarray:
        """
        Generate a 3D chaotic tensor for encryption operations.
        
        Args:
            mu: Chaos factor
            x0: Initial condition
            shape: Tensor dimensions (default: instance tensor_shape)
            cache_key: Optional cache key
            
        Returns:
            np.ndarray: 3D tensor of chaotic values in (0, 1)
        """
        shape = shape if shape is not None else self.tensor_shape
        total_elements = np.prod(shape)
        
        # Generate flat sequence
        sequence = self.generate_sequence(
            mu=mu,
            x0=x0,
            iterations=total_elements,
            cache_key=cache_key
        )
        
        # Reshape to 3D tensor
        tensor = sequence.reshape(shape)
        return tensor
    
    def generate_permutation_indices(
        self,
        size: int,
        mu: Optional[float] = None,
        x0: Optional[float] = None,
        cache_key: Optional[str] = None
    ) -> np.ndarray:
        """
        Generate deterministic permutation indices for tensor shuffling.
        
        The indices are generated by sorting the chaotic sequence, which
        produces a unique permutation that can be recreated by anyone with
        the same (x₀, μ) parameters.
        
        Args:
            size: Number of elements to permute
            mu: Chaos factor
            x0: Initial condition
            cache_key: Optional cache key
            
        Returns:
            np.ndarray: Permutation indices (array of integers 0 to size-1)
        """
        sequence = self.generate_sequence(
            mu=mu,
            x0=x0,
            iterations=size,
            cache_key=cache_key
        )
        
        # Generate permutation by sorting
        # The argsort gives us the permutation indices
        indices = np.argsort(sequence)
        return indices.astype(np.int32)
    
    def generate_3d_permutation(
        self,
        shape: Optional[Tuple[int, int, int]] = None,
        mu: Optional[float] = None,
        x0: Optional[float] = None,
        strategy: str = "voxel_swap"
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Generate 3D permutation indices for voxel-level shuffling.
        
        Args:
            shape: Tensor dimensions
            mu: Chaos factor
            x0: Initial condition
            strategy: Permutation strategy ('voxel_swap', 'row_shift', 'bit_plane')
            
        Returns:
            Tuple of (x_indices, y_indices, z_indices) for 3D permutation
        """
        shape = shape if shape is not None else self.tensor_shape
        total_voxels = np.prod(shape)
        
        # Generate base permutation
        base_indices = self.generate_permutation_indices(
            size=total_voxels,
            mu=mu,
            x0=x0
        )
        
        # Convert flat indices to 3D coordinates
        coords = np.unravel_index(base_indices, shape)
        return coords[0], coords[1], coords[2]
    
    def derive_session_params(
        self,
        session_id: str,
        device_fingerprint: str,
        timestamp: Optional[float] = None
    ) -> Tuple[float, float]:
        """
        Derive session-specific chaos parameters from shared secrets.
        
        Creates deterministic (x₀, μ) values that both parties can compute
        independently given the session ID and device fingerprints.
        
        Args:
            session_id: Unique session identifier
            device_fingerprint: Combined device fingerprint
            timestamp: Optional timestamp for additional entropy
            
        Returns:
            Tuple of (x0, mu) for the session
        """
        # Combine inputs
        timestamp = timestamp if timestamp is not None else 0.0
        combined = f"{session_id}:{device_fingerprint}:{timestamp}"
        
        # Hash to get deterministic bytes
        hash_bytes = hashlib.sha256(combined.encode()).digest()
        
        # Extract mu from first 8 bytes (in chaotic range [3.57, 4.0])
        mu_int = int.from_bytes(hash_bytes[:8], byteorder='big')
        mu = 3.57 + (mu_int % (2**48)) / (2**48) * 0.43  # Scale to [3.57, 4.0]
        
        # Extract x0 from next 8 bytes (in (0, 1), avoiding forbidden values)
        x0_int = int.from_bytes(hash_bytes[8:16], byteorder='big')
        x0 = (x0_int % (2**60)) / (2**60)  # Scale to (0, 1)
        
        # Ensure x0 is not a forbidden value
        for forbidden in self.FORBIDDEN_X0_VALUES:
            if abs(x0 - forbidden) < 0.01:
                x0 = (x0 + 0.001) % 1.0
                if x0 == 0.0:
                    x0 = 0.001
                break
        
        return x0, mu
    
    def clear_cache(self):
        """Clear all cached sequences"""
        self._sequence_cache.clear()
        self.sequence = None
    
    def get_entropy_estimate(self, sequence: Optional[np.ndarray] = None) -> float:
        """
        Estimate the entropy of a chaotic sequence.
        
        Uses histogram-based entropy estimation on the sequence distribution.
        
        Args:
            sequence: Sequence to analyze (uses instance sequence if None)
            
        Returns:
            float: Estimated entropy in bits
        """
        if sequence is None:
            if self.sequence is None:
                self.sequence = self.generate_sequence()
            sequence = self.sequence
        
        # Normalize to [0, 1] and create histogram
        n_bins = min(256, len(sequence) // 10)
        hist, _ = np.histogram(sequence, bins=n_bins, range=(0, 1), density=True)
        
        # Remove zero probabilities
        hist = hist[hist > 0]
        
        # Calculate Shannon entropy
        entropy = -np.sum(hist * np.log2(hist)) / n_bins
        
        return float(entropy)
    
    def __repr__(self) -> str:
        return (
            f"ChaosEngine(mu={self.params.mu:.6f}, "
            f"x0={self.params.x0:.6f}, "
            f"iterations={self.params.iterations}, "
            f"shape={self.tensor_shape})"
        )
