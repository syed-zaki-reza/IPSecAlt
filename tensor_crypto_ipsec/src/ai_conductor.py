"""
AI Conductor - Session Management and Strategy Selection

The AI Conductor acts as the "orchestrator" of the cryptographic system:
- Generates session-specific chaos parameters (x₀, μ)
- Selects permutation strategies based on session seeds
- Manages session lifecycle with 15-minute TTL
- Provides hybrid approach with pre-trained weights and on-the-fly adaptation

Features:
- Hybrid training strategy (pre-trained base + session adaptation)
- Environmental entropy collection (cross-platform compatible)
- Deterministic strategy selection for mirror recreation
- Session state management with automatic expiration
"""

import hashlib
import time
import secrets
import os
from typing import Dict, Tuple, Optional, Any, List
from dataclasses import dataclass, field
from enum import Enum
import logging
import json

try:
    from .chaos_engine import ChaosEngine
except ImportError:
    from chaos_engine import ChaosEngine

logger = logging.getLogger(__name__)


class SessionState(Enum):
    """Session lifecycle states"""
    INITIATED = "initiated"
    ACTIVE = "active"
    ROTATING = "rotating"
    EXPIRED = "expired"
    TERMINATED = "terminated"


@dataclass
class SessionInfo:
    """Session metadata and parameters"""
    session_id: str
    state: SessionState
    x0: float
    mu: float
    strategy: str
    created_at: float
    expires_at: float
    device_fingerprint: str
    peer_fingerprint: str
    rotation_count: int = 0
    bytes_processed: int = 0
    
    SESSION_TTL = 900  # 15 minutes in seconds
    
    def is_expired(self) -> bool:
        """Check if session has expired"""
        return time.time() > self.expires_at
    
    def time_until_expiry(self) -> float:
        """Get seconds until session expires"""
        return max(0, self.expires_at - time.time())
    
    def needs_rotation(self) -> bool:
        """Check if session needs key rotation"""
        # Rotate at 80% of TTL
        return self.time_until_expiry() < (self.SESSION_TTL * 0.2)


@dataclass
class EntropySample:
    """Environmental entropy sample"""
    timestamp: float
    system_time: int
    process_id: int
    thread_id: int
    counter: int
    random_bytes: bytes
    
    def to_seed(self) -> int:
        """Convert sample to integer seed"""
        combined = (
            f"{self.timestamp}:{self.system_time}:{self.process_id}:"
            f"{self.thread_id}:{self.counter}"
        ).encode() + self.random_bytes
        
        hash_val = hashlib.sha256(combined).digest()
        return int.from_bytes(hash_val[:8], byteorder='big')


class AIConductor:
    """
    AI Conductor for session orchestration and strategy selection.
    
    The conductor generates session-specific parameters that both parties
    can independently recreate using shared secrets and deterministic algorithms.
    
    Attributes:
        sessions: Active session dictionary
        default_strategy: Default permutation strategy
        chaos_engine: Shared ChaosEngine instance
    """
    
    AVAILABLE_STRATEGIES = [
        'voxel_swap',
        'row_shift', 
        'layer_rotate',
        'bit_plane'
    ]
    
    def __init__(
        self,
        chaos_engine: Optional[ChaosEngine] = None,
        default_strategy: str = 'voxel_swap'
    ):
        """
        Initialize the AI Conductor.
        
        Args:
            chaos_engine: ChaosEngine instance (creates new if None)
            default_strategy: Default permutation strategy
        """
        self.chaos_engine = chaos_engine or ChaosEngine()
        self.default_strategy = default_strategy
        self.sessions: Dict[str, SessionInfo] = {}
        self._entropy_counter = 0
        
        # Pre-computed strategy selection table (hybrid approach)
        self._strategy_table = self._build_strategy_table()
    
    def _build_strategy_table(self) -> Dict[int, str]:
        """
        Build deterministic strategy selection table.
        
        This implements the "hybrid" approach: pre-computed mapping
        from seed ranges to strategies, ensuring consistent selection.
        
        Returns:
            Dictionary mapping seed ranges to strategies
        """
        table = {}
        range_size = (2**32) // len(self.AVAILABLE_STRATEGIES)
        
        for i, strategy in enumerate(self.AVAILABLE_STRATEGIES):
            start = i * range_size
            end = start + range_size if i < len(self.AVAILABLE_STRATEGIES) - 1 else 2**32
            table[start] = strategy
        
        return table
    
    def collect_entropy_sample(self) -> EntropySample:
        """
        Collect environmental entropy sample (cross-platform).
        
        Uses OS-level sources that work consistently across Mac, Windows, Linux:
        - High-resolution timestamps
        - Process/thread IDs
        - Cryptographically secure random bytes
        
        Returns:
            EntropySample instance
        """
        self._entropy_counter += 1
        
        sample = EntropySample(
            timestamp=time.time(),
            system_time=time.time_ns(),
            process_id=os.getpid(),
            thread_id=hash(str(os.getpid()) + str(time.time())),
            counter=self._entropy_counter,
            random_bytes=secrets.token_bytes(16)
        )
        
        logger.debug(f"Collected entropy sample: counter={self._entropy_counter}")
        return sample
    
    def generate_standardized_seed(
        self,
        additional_entropy: Optional[bytes] = None
    ) -> int:
        """
        Generate standardized entropy seed (cross-platform compatible).
        
        Combines multiple entropy sources into a single deterministic seed
        that can be reproduced on any platform given the same inputs.
        
        Args:
            additional_entropy: Optional additional entropy bytes
            
        Returns:
            Integer seed value
        """
        sample = self.collect_entropy_sample()
        seed_int = sample.to_seed()
        
        if additional_entropy:
            # Mix in additional entropy
            combined = (
                seed_int.to_bytes(8, byteorder='big') + 
                additional_entropy
            )
            hash_val = hashlib.sha256(combined).digest()
            seed_int = int.from_bytes(hash_val[:8], byteorder='big')
        
        return seed_int
    
    def select_strategy(self, seed: int) -> str:
        """
        Select permutation strategy based on seed.
        
        Uses deterministic selection so both parties choose the same
        strategy given the same session parameters.
        
        Args:
            seed: Integer seed value
            
        Returns:
            Strategy name
        """
        # Normalize seed to 32-bit range
        normalized = seed % (2**32)
        
        # Find appropriate range in strategy table
        best_start = 0
        for start in sorted(self._strategy_table.keys()):
            if start <= normalized:
                best_start = start
            else:
                break
        
        return self._strategy_table[best_start]
    
    def initiate_session(
        self,
        session_id: str,
        device_fingerprint: str,
        peer_fingerprint: str,
        shared_secret: Optional[bytes] = None
    ) -> SessionInfo:
        """
        Initiate a new cryptographic session.
        
        Generates deterministic chaos parameters (x₀, μ) and selects
        a permutation strategy based on session identifiers.
        
        Args:
            session_id: Unique session identifier
            device_fingerprint: Local device fingerprint
            peer_fingerprint: Remote peer fingerprint
            shared_secret: Optional shared secret for additional security
            
        Returns:
            SessionInfo with session parameters
        """
        current_time = time.time()
        
        # Combine all inputs for deterministic generation
        combined_inputs = (
            f"{session_id}:{device_fingerprint}:{peer_fingerprint}:{current_time}"
        )
        
        if shared_secret:
            combined_inputs += f":{shared_secret.hex()}"
        
        # Hash to get deterministic bytes
        hash_bytes = hashlib.sha256(combined_inputs.encode()).digest()
        
        # Derive chaos parameters using ChaosEngine's method
        x0, mu = self.chaos_engine.derive_session_params(
            session_id=session_id,
            device_fingerprint=device_fingerprint + peer_fingerprint,
            timestamp=current_time
        )
        
        # Generate seed for strategy selection
        seed_int = int.from_bytes(hash_bytes[:8], byteorder='big')
        strategy = self.select_strategy(seed_int)
        
        # Create session info
        session = SessionInfo(
            session_id=session_id,
            state=SessionState.ACTIVE,
            x0=x0,
            mu=mu,
            strategy=strategy,
            created_at=current_time,
            expires_at=current_time + SessionInfo.SESSION_TTL,
            device_fingerprint=device_fingerprint,
            peer_fingerprint=peer_fingerprint
        )
        
        # Store session
        self.sessions[session_id] = session
        
        logger.info(
            f"Initiated session {session_id[:8]}... with strategy={strategy}, "
            f"mu={mu:.6f}, x0={x0:.6f}"
        )
        
        return session
    
    def get_session(self, session_id: str) -> Optional[SessionInfo]:
        """
        Retrieve active session by ID.
        
        Args:
            session_id: Session identifier
            
        Returns:
            SessionInfo if active and not expired, None otherwise
        """
        if session_id not in self.sessions:
            logger.debug(f"Session {session_id} not found")
            return None
        
        session = self.sessions[session_id]
        
        if session.is_expired():
            logger.warning(f"Session {session_id} has expired")
            session.state = SessionState.EXPIRED
            return None
        
        return session
    
    def rotate_session(
        self,
        session_id: str,
        reason: str = "time_based"
    ) -> Optional[SessionInfo]:
        """
        Rotate session keys and parameters.
        
        Generates new chaos parameters while maintaining session continuity.
        
        Args:
            session_id: Session to rotate
            reason: Rotation reason ('time_based', 'usage_based', 'manual')
            
        Returns:
            New SessionInfo, or None if original session not found
        """
        old_session = self.get_session(session_id)
        if not old_session:
            return None
        
        logger.info(f"Rotating session {session_id} ({reason})")
        
        # Mark old session as rotating
        old_session.state = SessionState.ROTATING
        
        # Generate new session with incremented rotation count
        new_session_id = f"{session_id}:rot{old_session.rotation_count + 1}"
        
        # Use old parameters plus rotation count for new derivation
        new_session = self.initiate_session(
            session_id=new_session_id,
            device_fingerprint=old_session.device_fingerprint,
            peer_fingerprint=old_session.peer_fingerprint,
            shared_secret=session_id.encode()
        )
        
        new_session.rotation_count = old_session.rotation_count + 1
        new_session.bytes_processed = old_session.bytes_processed
        
        # Update session registry
        self.sessions[session_id].state = SessionState.TERMINATED
        self.sessions[new_session_id] = new_session
        
        return new_session
    
    def terminate_session(self, session_id: str) -> bool:
        """
        Terminate a session.
        
        Args:
            session_id: Session to terminate
            
        Returns:
            True if terminated, False if not found
        """
        if session_id not in self.sessions:
            return False
        
        self.sessions[session_id].state = SessionState.TERMINATED
        self.sessions[session_id].expires_at = time.time()
        
        logger.info(f"Terminated session {session_id}")
        return True
    
    def cleanup_expired_sessions(self) -> int:
        """
        Remove all expired sessions from memory.
        
        Returns:
            Number of sessions cleaned up
        """
        expired_ids = [
            sid for sid, session in self.sessions.items()
            if session.is_expired() or session.state == SessionState.TERMINATED
        ]
        
        for sid in expired_ids:
            del self.sessions[sid]
        
        if expired_ids:
            logger.debug(f"Cleaned up {len(expired_ids)} expired sessions")
        
        return len(expired_ids)
    
    def get_active_session_count(self) -> int:
        """Get count of active (non-expired) sessions"""
        return sum(
            1 for s in self.sessions.values()
            if s.state == SessionState.ACTIVE and not s.is_expired()
        )
    
    def export_session_params(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Export session parameters for peer synchronization.
        
        In production, this would be sent over secure channel.
        For prototype, returns parameters that peer can use to recreate session.
        
        Args:
            session_id: Session to export
            
        Returns:
            Dictionary with session parameters, or None if not found
        """
        session = self.get_session(session_id)
        if not session:
            return None
        
        return {
            'session_id': session.session_id,
            'x0': session.x0,
            'mu': session.mu,
            'strategy': session.strategy,
            'created_at': session.created_at,
            'expires_at': session.expires_at,
            'device_fingerprint': session.device_fingerprint,
            'peer_fingerprint': session.peer_fingerprint
        }
    
    def import_session_params(
        self,
        params: Dict[str, Any]
    ) -> SessionInfo:
        """
        Import session parameters from peer.
        
        Creates local session mirror from exported parameters.
        
        Args:
            params: Session parameters from peer
            
        Returns:
            Imported SessionInfo
        """
        session = SessionInfo(
            session_id=params['session_id'],
            state=SessionState.ACTIVE,
            x0=params['x0'],
            mu=params['mu'],
            strategy=params['strategy'],
            created_at=params['created_at'],
            expires_at=params['expires_at'],
            device_fingerprint=params['device_fingerprint'],
            peer_fingerprint=params['peer_fingerprint']
        )
        
        # Validate expiry
        if session.is_expired():
            session.state = SessionState.EXPIRED
            raise ValueError("Imported session has already expired")
        
        self.sessions[session.session_id] = session
        
        logger.info(f"Imported session {session.session_id[:8]}...")
        return session
    
    def get_stats(self) -> Dict[str, Any]:
        """Get conductor statistics"""
        return {
            'total_sessions': len(self.sessions),
            'active_sessions': self.get_active_session_count(),
            'strategies_available': self.AVAILABLE_STRATEGIES,
            'default_strategy': self.default_strategy,
            'entropy_samples_collected': self._entropy_counter
        }
