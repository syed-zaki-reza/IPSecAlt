"""
Tensor-Based Post-Quantum Cryptography System

A quantum-resistant cryptographic protocol leveraging chaotic tensor mappings,
AI-driven orchestration, and hardware-rooted key provisioning as an alternative to IPsec.

Core Innovation: Decoupled Cryptographic Orchestration using:
- 3D Chaotic Tensor Mappings (Logistic Map-based)
- AI Conductor for session-specific strategy selection
- Deterministic permutation recreation via Mirror Chaos Engine
"""

__version__ = "0.1.0"
__author__ = "Research Prototype"

from .chaos_engine import ChaosEngine
from .tensor_engine import TensorEngine
from .ai_conductor import AIConductor
from .key_management import KeyManager
from .dictionary_manager import DictionaryManager
from .router_interface import RouterInterface
from .utils import (
    generate_device_fingerprint,
    calculate_entropy,
    constant_time_compare,
    PerformanceMonitor
)

__all__ = [
    "ChaosEngine",
    "TensorEngine",
    "AIConductor",
    "KeyManager",
    "DictionaryManager",
    "RouterInterface",
    "generate_device_fingerprint",
    "calculate_entropy",
    "constant_time_compare",
    "PerformanceMonitor",
]
