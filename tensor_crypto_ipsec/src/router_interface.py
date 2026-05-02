"""
Router Interface - Network Protocol Simulation & Packet Handling

Implements network-layer packet handling for tensor-based encryption.
Supports TCP/UDP/simulation modes with secure handshaking.

Features:
- 32-byte packet header with checksum
- Session state machine management
- Encrypted packet transmission simulation
- Peer-to-peer communication simulation
"""

import hashlib
import time
import socket
import threading
from typing import Dict, Optional, Any, List, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
import logging
import json
import struct

logger = logging.getLogger(__name__)


class PacketType(Enum):
    """Packet types for protocol"""
    HANDSHAKE_INIT = 1
    HANDSHAKE_RESP = 2
    DATA = 3
    KEY_ROTATE = 4
    TERMINATE = 5
    ACK = 6


class SessionState(Enum):
    """Session state machine states"""
    IDLE = "idle"
    HANDSHAKE_INITIATED = "handshake_initiated"
    HANDSHAKE_RESPONDING = "handshake_responding"
    ESTABLISHED = "established"
    KEY_ROTATING = "key_rotating"
    ERROR = "error"
    TERMINATED = "terminated"


@dataclass
class PacketHeader:
    """
    32-byte packet header structure.
    
    Layout:
    - byte 0: packet_type (uint8)
    - bytes 1-4: payload_size (uint32)
    - byte 5: src_len (uint8)
    - bytes 6-...: src_address (variable)
    - ...: dst_address (variable)
    - ...: session_id (variable)
    - ...: sequence number (uint32)
    - ...: timestamp (uint64)
    - ...: checksum (variable)
    """
    packet_type: PacketType
    payload_size: int
    src_address: bytes
    dst_address: bytes
    session_id: bytes
    sequence: int
    timestamp: float
    checksum: bytes
    
    HEADER_MIN_SIZE = 23  # Minimum header without addresses
    
    def serialize(self) -> bytes:
        """Serialize header to bytes"""
        data = bytearray()
        
        # Packet type (1 byte)
        data.append(self.packet_type.value)
        
        # Payload size (4 bytes)
        data.extend(struct.pack('>I', self.payload_size))
        
        # Source address (1 byte len + data)
        data.append(len(self.src_address))
        data.extend(self.src_address)
        
        # Destination address (1 byte len + data)
        data.append(len(self.dst_address))
        data.extend(self.dst_address)
        
        # Session ID (1 byte len + data)
        data.append(len(self.session_id))
        data.extend(self.session_id)
        
        # Sequence number (4 bytes)
        data.extend(struct.pack('>I', self.sequence))
        
        # Timestamp (8 bytes)
        data.extend(struct.pack('>Q', int(self.timestamp * 1000)))
        
        # Checksum (1 byte len + data)
        data.append(len(self.checksum))
        data.extend(self.checksum)
        
        return bytes(data)
    
    @classmethod
    def deserialize(cls, data: bytes) -> Tuple['PacketHeader', bytes]:
        """Deserialize header from bytes, return header and remaining payload"""
        offset = 0
        
        # Packet type
        packet_type = PacketType(data[offset])
        offset += 1
        
        # Payload size
        payload_size = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        
        # Source address
        src_len = data[offset]
        offset += 1
        src_address = data[offset:offset+src_len]
        offset += src_len
        
        # Destination address
        dst_len = data[offset]
        offset += 1
        dst_address = data[offset:offset+dst_len]
        offset += dst_len
        
        # Session ID
        session_len = data[offset]
        offset += 1
        session_id = data[offset:offset+session_len]
        offset += session_len
        
        # Sequence
        sequence = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        
        # Timestamp
        timestamp_ms = struct.unpack('>Q', data[offset:offset+8])[0]
        timestamp = timestamp_ms / 1000.0
        offset += 8
        
        # Checksum
        checksum_len = data[offset]
        offset += 1
        checksum = data[offset:offset+checksum_len]
        offset += checksum_len
        
        header = cls(
            packet_type=packet_type,
            payload_size=payload_size,
            src_address=src_address,
            dst_address=dst_address,
            session_id=session_id,
            sequence=sequence,
            timestamp=timestamp,
            checksum=checksum
        )
        
        return header, data[offset:]


@dataclass
class SessionContext:
    """Session state and parameters"""
    session_id: str
    state: SessionState
    local_address: bytes
    remote_address: bytes
    created_at: float
    last_activity: float
    sequence_in: int = 0
    sequence_out: int = 0
    mu: float = 4.0
    x0: float = 0.5
    strategy: str = 'voxel_swap'
    error_message: str = ""


class RouterInterface:
    """
    Router Interface for Network Protocol Simulation.
    
    Simulates router-to-router communication with tensor encryption.
    Supports in-memory simulation mode for testing.
    
    Attributes:
        address: Local router address identifier
        sessions: Active session registry
        mode: Operation mode ('simulation', 'tcp', 'udp')
    """
    
    def __init__(
        self,
        address: str = "router_0",
        mode: str = "simulation"
    ):
        """
        Initialize Router Interface.
        
        Args:
            address: Local router identifier
            mode: Operation mode
        """
        self.address = address.encode()
        self.mode = mode
        self.sessions: Dict[str, SessionContext] = {}
        self._lock = threading.RLock()
        
        # Callbacks for external integration
        self._encrypt_callback: Optional[Callable] = None
        self._decrypt_callback: Optional[Callable] = None
        
        # Statistics
        self._packets_sent = 0
        self._packets_received = 0
        self._bytes_transmitted = 0
        
        logger.info(f"Router interface initialized: {address} ({mode})")
    
    def set_crypto_callbacks(
        self,
        encrypt_func: Callable,
        decrypt_func: Callable
    ):
        """Set encryption/decryption callbacks"""
        self._encrypt_callback = encrypt_func
        self._decrypt_callback = decrypt_func
    
    def _compute_checksum(self, data: bytes) -> bytes:
        """Compute packet checksum"""
        return hashlib.md5(data).digest()[:8]
    
    def _create_packet(
        self,
        packet_type: PacketType,
        payload: bytes,
        session_id: str,
        dst_address: bytes
    ) -> bytes:
        """Create complete packet with header and payload"""
        # Get or create session
        session = self.sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        # Increment sequence
        session.sequence_out += 1
        
        # Create header
        header = PacketHeader(
            packet_type=packet_type,
            payload_size=len(payload),
            src_address=self.address,
            dst_address=dst_address,
            session_id=session_id.encode(),
            sequence=session.sequence_out,
            timestamp=time.time(),
            checksum=b''
        )
        
        # Serialize header without checksum first
        header_data = header.serialize()[:-9]  # Remove checksum portion
        
        # Compute checksum over header + payload
        checksum_data = header_data + payload
        checksum = self._compute_checksum(checksum_data)
        
        # Update header with checksum
        header.checksum = checksum
        full_header = header.serialize()
        
        return full_header + payload
    
    def _parse_packet(self, data: bytes) -> Tuple[PacketHeader, bytes, bool]:
        """Parse packet, return header, payload, and verification status"""
        try:
            header, payload = PacketHeader.deserialize(data)
            
            # Verify checksum
            # Reconstruct header without checksum
            header_bytes = bytearray()
            header_bytes.append(header.packet_type.value)
            header_bytes.extend(struct.pack('>I', header.payload_size))
            header_bytes.append(len(header.src_address))
            header_bytes.extend(header.src_address)
            header_bytes.append(len(header.dst_address))
            header_bytes.extend(header.dst_address)
            header_bytes.append(len(header.session_id))
            header_bytes.extend(header.session_id)
            header_bytes.extend(struct.pack('>I', header.sequence))
            header_bytes.extend(struct.pack('>Q', int(header.timestamp * 1000)))
            
            checksum_data = bytes(header_bytes) + payload
            expected_checksum = self._compute_checksum(checksum_data)
            
            verified = header.checksum == expected_checksum
            
            return header, payload, verified
            
        except Exception as e:
            logger.error(f"Packet parse error: {e}")
            raise
    
    def initiate_handshake(
        self,
        peer_address: str,
        session_id: str,
        initial_params: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Initiate handshake with peer.
        
        Args:
            peer_address: Peer router address
            session_id: Session identifier
            initial_params: Initial chaos parameters
            
        Returns:
            True if handshake initiated successfully
        """
        with self._lock:
            current_time = time.time()
            
            # Create session context
            session = SessionContext(
                session_id=session_id,
                state=SessionState.HANDSHAKE_INITIATED,
                local_address=self.address,
                remote_address=peer_address.encode(),
                created_at=current_time,
                last_activity=current_time
            )
            
            # Set initial parameters
            if initial_params:
                session.mu = initial_params.get('mu', 4.0)
                session.x0 = initial_params.get('x0', 0.5)
                session.strategy = initial_params.get('strategy', 'voxel_swap')
            
            self.sessions[session_id] = session
            
            # Create handshake packet
            payload = json.dumps({
                'type': 'handshake_init',
                'params': {
                    'mu': session.mu,
                    'x0': session.x0,
                    'strategy': session.strategy
                },
                'timestamp': current_time
            }).encode()
            
            packet = self._create_packet(
                PacketType.HANDSHAKE_INIT,
                payload,
                session_id,
                peer_address.encode()
            )
            
            # In simulation mode, store packet for peer retrieval
            if self.mode == 'simulation':
                self._store_simulated_packet(session_id, packet)
            
            logger.info(f"Initiated handshake with {peer_address} (session: {session_id[:8]}...)")
            return True
    
    def respond_to_handshake(
        self,
        packet_data: bytes
    ) -> Optional[bytes]:
        """
        Respond to received handshake initiation.
        
        Args:
            packet_data: Received handshake packet
            
        Returns:
            Response packet, or None on failure
        """
        try:
            header, payload, verified = self._parse_packet(packet_data)
            
            if not verified:
                logger.warning("Handshake packet checksum failed")
                return None
            
            if header.packet_type != PacketType.HANDSHAKE_INIT:
                return None
            
            # Parse handshake data
            data = json.loads(payload.decode())
            
            # Create/update session
            session_id = header.session_id.decode()
            
            with self._lock:
                session = SessionContext(
                    session_id=session_id,
                    state=SessionState.HANDSHAKE_RESPONDING,
                    local_address=self.address,
                    remote_address=header.src_address,
                    created_at=time.time(),
                    last_activity=time.time(),
                    mu=data['params'].get('mu', 4.0),
                    x0=data['params'].get('x0', 0.5),
                    strategy=data['params'].get('strategy', 'voxel_swap')
                )
                
                self.sessions[session_id] = session
            
            # Create response
            response_payload = json.dumps({
                'type': 'handshake_resp',
                'status': 'accepted',
                'timestamp': time.time()
            }).encode()
            
            response_packet = self._create_packet(
                PacketType.HANDSHAKE_RESP,
                response_payload,
                session_id,
                header.src_address
            )
            
            # Transition to established
            session.state = SessionState.ESTABLISHED
            
            logger.info(f"Handshake responded for session {session_id[:8]}...")
            return response_packet
            
        except Exception as e:
            logger.error(f"Handshake response error: {e}")
            return None
    
    def send_encrypted_data(
        self,
        session_id: str,
        plaintext: bytes
    ) -> Optional[bytes]:
        """
        Send encrypted data to peer.
        
        Args:
            session_id: Session identifier
            plaintext: Data to encrypt and send
            
        Returns:
            Encrypted packet, or None on failure
        """
        with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                logger.error(f"Session {session_id} not found")
                return None
            
            if session.state != SessionState.ESTABLISHED:
                logger.error(f"Session {session_id} not in ESTABLISHED state")
                return None
        
        # Encrypt using callback
        if self._encrypt_callback:
            ciphertext = self._encrypt_callback(
                plaintext,
                session.mu,
                session.x0,
                session_id
            ).ciphertext
        else:
            logger.warning("No encrypt callback set, sending unencrypted")
            ciphertext = plaintext
        
        # Create data packet
        packet = self._create_packet(
            PacketType.DATA,
            ciphertext,
            session_id,
            session.remote_address
        )
        
        # Update statistics
        self._packets_sent += 1
        self._bytes_transmitted += len(packet)
        
        # Store for simulation
        if self.mode == 'simulation':
            self._store_simulated_packet(session_id, packet)
        
        return packet
    
    def receive_data(
        self,
        packet_data: bytes
    ) -> Optional[bytes]:
        """
        Receive and decrypt data packet.
        
        Args:
            packet_data: Received packet
            
        Returns:
            Decrypted plaintext, or None on failure
        """
        try:
            header, payload, verified = self._parse_packet(packet_data)
            
            if not verified:
                logger.warning("Data packet checksum failed")
                return None
            
            if header.packet_type != PacketType.DATA:
                return None
            
            session_id = header.session_id.decode()
            
            with self._lock:
                session = self.sessions.get(session_id)
                if not session:
                    logger.error(f"Session {session_id} not found")
                    return None
                
                session.last_activity = time.time()
                session.sequence_in = header.sequence
            
            # Decrypt using callback
            if self._decrypt_callback:
                result = self._decrypt_callback(
                    payload,
                    session.mu,
                    session.x0,
                    session_id
                )
                return result.plaintext
            else:
                logger.warning("No decrypt callback set, returning raw payload")
                return payload
                
        except Exception as e:
            logger.error(f"Data receive error: {e}")
            return None
    
    def _store_simulated_packet(self, session_id: str, packet: bytes):
        """Store packet in simulation buffer"""
        # In real implementation, this would use network sockets
        # For simulation, we store in a class-level buffer
        if not hasattr(RouterInterface, '_sim_buffer'):
            RouterInterface._sim_buffer = {}
        
        if session_id not in RouterInterface._sim_buffer:
            RouterInterface._sim_buffer[session_id] = []
        
        RouterInterface._sim_buffer[session_id].append(packet)
    
    def get_simulated_packets(self, session_id: str) -> List[bytes]:
        """Retrieve packets from simulation buffer"""
        if not hasattr(RouterInterface, '_sim_buffer'):
            return []
        
        packets = RouterInterface._sim_buffer.get(session_id, [])
        RouterInterface._sim_buffer[session_id] = []  # Clear after retrieval
        return packets
    
    def terminate_session(self, session_id: str) -> bool:
        """Terminate a session"""
        with self._lock:
            if session_id not in self.sessions:
                return False
            
            self.sessions[session_id].state = SessionState.TERMINATED
            logger.info(f"Terminated session {session_id}")
            return True
    
    def get_session_state(self, session_id: str) -> Optional[SessionState]:
        """Get current session state"""
        session = self.sessions.get(session_id)
        return session.state if session else None
    
    def get_stats(self) -> Dict[str, Any]:
        """Get interface statistics"""
        with self._lock:
            return {
                'address': self.address.decode(),
                'mode': self.mode,
                'active_sessions': sum(
                    1 for s in self.sessions.values()
                    if s.state == SessionState.ESTABLISHED
                ),
                'total_sessions': len(self.sessions),
                'packets_sent': self._packets_sent,
                'packets_received': self._packets_received,
                'bytes_transmitted': self._bytes_transmitted
            }
