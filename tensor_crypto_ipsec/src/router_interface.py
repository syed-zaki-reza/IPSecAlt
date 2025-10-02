"""
router_interface.py
Network Interface and Protocol Simulation for Tensor-Based Post-Quantum Cryptography

This module implements network communication protocols, packet handling, and router
integration for the tensor-based cryptographic system. It provides secure handshaking,
encrypted data transmission, and network protocol simulation suitable for IPsec replacement.
"""

import numpy as np
import socket
import struct
import threading
import time
import json
import logging
import queue
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
import asyncio
import ssl
from collections import defaultdict, deque

# Import our crypto components
from tensor_engine import TensorEncryptionEngine
from ai_logic import AILogicGenerator
from dictionary_manager import DynamicDictionaryManager
from key_management import KeyManager, KeyType


class PacketType(Enum):
    """Network packet types for the protocol"""
    HANDSHAKE_INIT = 0x01
    HANDSHAKE_RESPONSE = 0x02
    HANDSHAKE_COMPLETE = 0x03
    DATA_ENCRYPTED = 0x10
    DATA_BROADCAST = 0x11
    KEY_ROTATION = 0x20
    DICT_SYNC = 0x21
    HEARTBEAT = 0x30
    ERROR = 0xF0
    DISCONNECT = 0xFF


class SessionState(Enum):
    """Session state machine states"""
    IDLE = "idle"
    HANDSHAKE_INITIATED = "handshake_initiated"
    HANDSHAKE_RESPONDING = "handshake_responding"
    ESTABLISHED = "established"
    KEY_ROTATING = "key_rotating"
    ERROR = "error"
    TERMINATED = "terminated"


class NetworkProtocol(Enum):
    """Supported network protocols"""
    TCP = "tcp"
    UDP = "udp"
    SIMULATION = "simulation"


@dataclass
class NetworkPacket:
    """Network packet structure"""
    packet_type: PacketType
    source_id: str
    destination_id: str
    session_id: str
    sequence_number: int
    payload: bytes
    timestamp: float
    checksum: str
    signature: Optional[bytes] = None


@dataclass
class SessionInfo:
    """Session information and state"""
    session_id: str
    peer_device_id: str
    state: SessionState
    created_at: datetime
    last_activity: datetime
    tensor_key_id: str
    ai_logic_data: Optional[np.ndarray]
    dictionary_id: str
    sequence_number: int
    peer_sequence: int
    encryption_params: Dict[str, Any]
    network_stats: Dict[str, int]


class RouterInterface:
    """
    Network interface and protocol handler for tensor-based cryptography
    
    Provides secure communication protocols, packet handling, session management,
    and integration with router hardware for IPsec replacement functionality.
    """
    
    def __init__(self,
                 tensor_engine: TensorEncryptionEngine,
                 ai_logic: AILogicGenerator,
                 dict_manager: DynamicDictionaryManager,
                 key_manager: KeyManager,
                 device_id: str,
                 listen_port: int = 8443,
                 protocol: NetworkProtocol = NetworkProtocol.SIMULATION,
                 max_connections: int = 100):
        """
        Initialize router interface
        
        Args:
            tensor_engine: Tensor encryption engine
            ai_logic: AI logic generator
            dict_manager: Dictionary manager
            key_manager: Key manager
            device_id: Local device identifier
            listen_port: Port to listen on
            protocol: Network protocol to use
            max_connections: Maximum concurrent connections
        """
        self.tensor_engine = tensor_engine
        self.ai_logic = ai_logic
        self.dict_manager = dict_manager
        self.key_manager = key_manager
        self.device_id = device_id
        self.listen_port = listen_port
        self.protocol = protocol
        self.max_connections = max_connections
        
        # Initialize logging
        self.logger = logging.getLogger(__name__)
        
        # Session management
        self.active_sessions = {}  # {session_id: SessionInfo}
        self.peer_sessions = {}    # {peer_device_id: session_id}
        self.session_lock = threading.RLock()
        
        # Network components
        self.server_socket = None
        self.is_listening = False
        self.connection_handlers = {}
        self.message_handlers = {}
        
        # Packet processing
        self.packet_queue = queue.Queue(maxsize=1000)
        self.outbound_queue = queue.Queue(maxsize=1000)
        self.packet_processors = []
        
        # Thread pool for handling connections
        self.executor = ThreadPoolExecutor(
            max_workers=max_connections, 
            thread_name_prefix="router_handler"
        )
        
        # Performance metrics
        self.metrics = {
            'packets_sent': 0,
            'packets_received': 0,
            'handshakes_completed': 0,
            'sessions_established': 0,
            'key_rotations': 0,
            'encryption_operations': 0,
            'decryption_operations': 0,
            'network_errors': 0,
            'bytes_transmitted': 0,
            'bytes_received': 0
        }
        
        # Protocol configuration
        self.config = {
            'handshake_timeout': 30.0,  # seconds
            'session_timeout': 3600.0,  # 1 hour
            'heartbeat_interval': 60.0,  # 1 minute
            'max_packet_size': 65536,   # 64KB
            'retry_attempts': 3,
            'key_rotation_threshold': 1000000,  # 1MB of data
            'compression_enabled': True,
            'integrity_checking': True
        }
        
        # Initialize message handlers
        self._setup_message_handlers()
        
        # Network simulation components (for testing)
        if protocol == NetworkProtocol.SIMULATION:
            self.simulation_network = {}
            self.simulation_latency = 0.001  # 1ms default latency
        
        self.logger.info(f"Router Interface initialized for device {device_id}")
    
    def _setup_message_handlers(self):
        """Setup message type handlers"""
        self.message_handlers = {
            PacketType.HANDSHAKE_INIT: self._handle_handshake_init,
            PacketType.HANDSHAKE_RESPONSE: self._handle_handshake_response,
            PacketType.HANDSHAKE_COMPLETE: self._handle_handshake_complete,
            PacketType.DATA_ENCRYPTED: self._handle_encrypted_data,
            PacketType.DATA_BROADCAST: self._handle_broadcast_data,
            PacketType.KEY_ROTATION: self._handle_key_rotation,
            PacketType.DICT_SYNC: self._handle_dictionary_sync,
            PacketType.HEARTBEAT: self._handle_heartbeat,
            PacketType.ERROR: self._handle_error,
            PacketType.DISCONNECT: self._handle_disconnect
        }
    
    def start_listening(self) -> bool:
        """
        Start listening for incoming connections
        
        Returns:
            Success status
        """
        try:
            if self.protocol == NetworkProtocol.SIMULATION:
                # Simulation mode - no actual network socket
                self.is_listening = True
                self._start_packet_processors()
                self.logger.info(f"Started simulation listener on device {self.device_id}")
                return True
            
            elif self.protocol == NetworkProtocol.TCP:
                # Create TCP server socket
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind(('0.0.0.0', self.listen_port))
                self.server_socket.listen(self.max_connections)
                
                self.is_listening = True
                
                # Start accepting connections
                accept_thread = threading.Thread(
                    target=self._accept_connections,
                    daemon=True,
                    name="connection_acceptor"
                )
                accept_thread.start()
                
                self._start_packet_processors()
                
                self.logger.info(f"Started TCP listener on port {self.listen_port}")
                return True
            
            elif self.protocol == NetworkProtocol.UDP:
                # Create UDP socket
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.server_socket.bind(('0.0.0.0', self.listen_port))
                
                self.is_listening = True
                
                # Start UDP receiver
                udp_thread = threading.Thread(
                    target=self._handle_udp_packets,
                    daemon=True,
                    name="udp_handler"
                )
                udp_thread.start()
                
                self._start_packet_processors()
                
                self.logger.info(f"Started UDP listener on port {self.listen_port}")
                return True
            
        except Exception as e:
            self.logger.error(f"Failed to start listener: {e}")
            return False
    
    def stop_listening(self):
        """Stop listening and close all connections"""
        self.is_listening = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        # Close all active sessions
        with self.session_lock:
            for session_id in list(self.active_sessions.keys()):
                self.terminate_session(session_id)
        
        # Shutdown executor
        self.executor.shutdown(wait=True)
        
        self.logger.info("Router interface stopped")
    
    def _start_packet_processors(self):
        """Start packet processing threads"""
        # Input packet processor
        processor_thread = threading.Thread(
            target=self._packet_processor_worker,
            daemon=True,
            name="packet_processor"
        )
        processor_thread.start()
        self.packet_processors.append(processor_thread)
        
        # Output packet processor
        sender_thread = threading.Thread(
            target=self._packet_sender_worker,
            daemon=True,
            name="packet_sender"
        )
        sender_thread.start()
        self.packet_processors.append(sender_thread)
        
        # Session maintenance
        maintenance_thread = threading.Thread(
            target=self._session_maintenance_worker,
            daemon=True,
            name="session_maintenance"
        )
        maintenance_thread.start()
        self.packet_processors.append(maintenance_thread)
    
    def _accept_connections(self):
        """Accept incoming TCP connections"""
        while self.is_listening:
            try:
                client_socket, address = self.server_socket.accept()
                
                # Handle connection in thread pool
                future = self.executor.submit(
                    self._handle_tcp_connection, 
                    client_socket, address
                )
                
            except Exception as e:
                if self.is_listening:  # Only log if we're still supposed to be listening
                    self.logger.error(f"Error accepting connection: {e}")
                break
    
    def _handle_tcp_connection(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle individual TCP connection"""
        try:
            self.logger.debug(f"New TCP connection from {address}")
            
            while True:
                # Read packet header (fixed size)
                header_data = self._receive_exact(client_socket, 32)  # 32-byte header
                if not header_data:
                    break
                
                # Parse header
                packet_type, payload_size = struct.unpack('>BI', header_data[:5])
                
                # Read payload
                if payload_size > self.config['max_packet_size']:
                    self.logger.warning(f"Packet too large: {payload_size} bytes")
                    break
                
                payload_data = self._receive_exact(client_socket, payload_size)
                if not payload_data:
                    break
                
                # Create packet and queue for processing
                packet = self._deserialize_packet(header_data + payload_data)
                if packet:
                    self.packet_queue.put((packet, client_socket))
                    self.metrics['packets_received'] += 1
                    self.metrics['bytes_received'] += len(header_data) + len(payload_data)
                
        except Exception as e:
            self.logger.error(f"TCP connection error with {address}: {e}")
            self.metrics['network_errors'] += 1
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _handle_udp_packets(self):
        """Handle UDP packet reception"""
        while self.is_listening:
            try:
                data, address = self.server_socket.recvfrom(self.config['max_packet_size'])
                
                # Deserialize packet
                packet = self._deserialize_packet(data)
                if packet:
                    self.packet_queue.put((packet, address))
                    self.metrics['packets_received'] += 1
                    self.metrics['bytes_received'] += len(data)
                
            except Exception as e:
                if self.is_listening:
                    self.logger.error(f"UDP reception error: {e}")
                    self.metrics['network_errors'] += 1
    
    def _receive_exact(self, sock: socket.socket, size: int) -> Optional[bytes]:
        """Receive exact number of bytes from socket"""
        data = b''
        while len(data) < size:
            try:
                chunk = sock.recv(size - len(data))
                if not chunk:
                    return None
                data += chunk
            except Exception as e:
                self.logger.error(f"Socket receive error: {e}")
                return None
        return data
    
    def initiate_handshake(self, peer_device_id: str, 
                          peer_address: Optional[Tuple[str, int]] = None) -> Optional[str]:
        """
        Initiate handshake with peer device
        
        Args:
            peer_device_id: ID of peer device to connect to
            peer_address: Network address of peer (for real network)
            
        Returns:
            Session ID if successful, None otherwise
        """
        # Generate new session ID
        session_id = self._generate_session_id(peer_device_id)
        
        # Create session info
        session_info = SessionInfo(
            session_id=session_id,
            peer_device_id=peer_device_id,
            state=SessionState.HANDSHAKE_INITIATED,
            created_at=datetime.now(),
            last_activity=datetime.now(),
            tensor_key_id="",
            ai_logic_data=None,
            dictionary_id="",
            sequence_number=1,
            peer_sequence=0,
            encryption_params={},
            network_stats=defaultdict(int)
        )
        
        # Store session
        with self.session_lock:
            self.active_sessions[session_id] = session_info
            self.peer_sessions[peer_device_id] = session_id
        
        # Generate handshake payload
        handshake_payload = self._create_handshake_init_payload(session_id)
        
        # Create and send handshake packet
        packet = NetworkPacket(
            packet_type=PacketType.HANDSHAKE_INIT,
            source_id=self.device_id,
            destination_id=peer_device_id,
            session_id=session_id,
            sequence_number=session_info.sequence_number,
            payload=handshake_payload,
            timestamp=time.time(),
            checksum=""
        )
        
        packet.checksum = self._calculate_packet_checksum(packet)
        
        # Send packet
        success = self._send_packet(packet, peer_address)
        
        if success:
            session_info.sequence_number += 1
            self.logger.info(f"Handshake initiated with {peer_device_id}, session {session_id[:16]}...")
            return session_id
        else:
            # Clean up failed session
            with self.session_lock:
                if session_id in self.active_sessions:
                    del self.active_sessions[session_id]
                if peer_device_id in self.peer_sessions:
                    del self.peer_sessions[peer_device_id]
            return None
    
    def _generate_session_id(self, peer_device_id: str) -> str:
        """Generate unique session identifier"""
        timestamp = int(time.time() * 1000000)
        entropy = secrets.token_hex(8)
        combined = f"{self.device_id}_{peer_device_id}_{timestamp}_{entropy}"
        session_hash = hashlib.sha256(combined.encode()).hexdigest()[:32]
        return f"session_{session_hash}"
    
    def _create_handshake_init_payload(self, session_id: str) -> bytes:
        """Create handshake initialization payload"""
        handshake_data = {
            'protocol_version': '1.0',
            'device_capabilities': {
                'tensor_dimensions': self.tensor_engine.tensor_dims,
                'security_level': self.tensor_engine.security_level,
                'ai_logic_enabled': True,
                'dictionary_sync': True
            },
            'supported_algorithms': ['tensor-xor', 'ai-enhanced', 'dict-lookup'],
            'nonce': secrets.token_hex(32),
            'timestamp': time.time()
        }
        
        payload_json = json.dumps(handshake_data).encode('utf-8')
        
        # Add HMAC for integrity
        key_id, hmac_key = self.key_manager.derive_key(
            KeyType.EPHEMERAL, f'handshake_{session_id}'
        )
        
        mac = hmac.new(hmac_key, payload_json, hashlib.sha256).digest()
        
        return payload_json + b'|HMAC|' + mac
    
    def _send_packet(self, packet: NetworkPacket, 
                    destination: Optional[Tuple[str, int]] = None) -> bool:
        """Send network packet"""
        try:
            # Serialize packet
            packet_data = self._serialize_packet(packet)
            
            if self.protocol == NetworkProtocol.SIMULATION:
                # Simulation mode
                return self._simulate_packet_send(packet, packet_data)
                
            elif self.protocol == NetworkProtocol.UDP and destination:
                # Send UDP packet
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(packet_data, destination)
                sock.close()
                
            elif self.protocol == NetworkProtocol.TCP and destination:
                # Send TCP packet
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(destination)
                sock.sendall(packet_data)
                sock.close()
            
            # Update metrics
            self.metrics['packets_sent'] += 1
            self.metrics['bytes_transmitted'] += len(packet_data)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send packet: {e}")
            self.metrics['network_errors'] += 1
            return False
    
    def _simulate_packet_send(self, packet: NetworkPacket, packet_data: bytes) -> bool:
        """Simulate packet transmission for testing"""
        # Add simulated network latency
        def delayed_delivery():
            time.sleep(self.simulation_latency)
            
            # Check if destination exists in simulation network
            if packet.destination_id in self.simulation_network:
                peer_interface = self.simulation_network[packet.destination_id]
                peer_interface.packet_queue.put((packet, None))
        
        # Schedule delayed delivery
        threading.Thread(target=delayed_delivery, daemon=True).start()
        return True
    
    def _serialize_packet(self, packet: NetworkPacket) -> bytes:
        """Serialize packet for network transmission"""
        # Packet header format:
        # - packet_type (1 byte)
        # - payload_size (4 bytes)
        # - source_id_len (1 byte) + source_id (variable)
        # - dest_id_len (1 byte) + dest_id (variable)
        # - session_id_len (1 byte) + session_id (variable)
        # - sequence_number (4 bytes)
        # - timestamp (8 bytes)
        # - checksum_len (1 byte) + checksum (variable)
        # - payload (variable)
        
        payload = packet.payload
        
        header = struct.pack('>B', packet.packet_type.value)  # packet_type
        header += struct.pack('>I', len(payload))  # payload_size
        
        # Source ID
        source_bytes = packet.source_id.encode('utf-8')
        header += struct.pack('>B', len(source_bytes)) + source_bytes
        
        # Destination ID
        dest_bytes = packet.destination_id.encode('utf-8')
        header += struct.pack('>B', len(dest_bytes)) + dest_bytes
        
        # Session ID
        session_bytes = packet.session_id.encode('utf-8')
        header += struct.pack('>B', len(session_bytes)) + session_bytes
        
        # Sequence number and timestamp
        header += struct.pack('>I', packet.sequence_number)
        header += struct.pack('>d', packet.timestamp)
        
        # Checksum
        checksum_bytes = packet.checksum.encode('utf-8')
        header += struct.pack('>B', len(checksum_bytes)) + checksum_bytes
        
        return header + payload
    
    def _deserialize_packet(self, data: bytes) -> Optional[NetworkPacket]:
        """Deserialize packet from network data"""
        try:
            offset = 0
            
            # Parse header
            packet_type = PacketType(struct.unpack('>B', data[offset:offset+1])[0])
            offset += 1
            
            payload_size = struct.unpack('>I', data[offset:offset+4])[0]
            offset += 4
            
            # Source ID
            source_len = struct.unpack('>B', data[offset:offset+1])[0]
            offset += 1
            source_id = data[offset:offset+source_len].decode('utf-8')
            offset += source_len
            
            # Destination ID
            dest_len = struct.unpack('>B', data[offset:offset+1])[0]
            offset += 1
            destination_id = data[offset:offset+dest_len].decode('utf-8')
            offset += dest_len
            
            # Session ID
            session_len = struct.unpack('>B', data[offset:offset+1])[0]
            offset += 1
            session_id = data[offset:offset+session_len].decode('utf-8')
            offset += session_len
            
            # Sequence and timestamp
            sequence_number = struct.unpack('>I', data[offset:offset+4])[0]
            offset += 4
            timestamp = struct.unpack('>d', data[offset:offset+8])[0]
            offset += 8
            
            # Checksum
            checksum_len = struct.unpack('>B', data[offset:offset+1])[0]
            offset += 1
            checksum = data[offset:offset+checksum_len].decode('utf-8')
            offset += checksum_len
            
            # Payload
            payload = data[offset:offset+payload_size]
            
            packet = NetworkPacket(
                packet_type=packet_type,
                source_id=source_id,
                destination_id=destination_id,
                session_id=session_id,
                sequence_number=sequence_number,
                payload=payload,
                timestamp=timestamp,
                checksum=checksum
            )
            
            return packet
            
        except Exception as e:
            self.logger.error(f"Failed to deserialize packet: {e}")
            return None
    
    def _calculate_packet_checksum(self, packet: NetworkPacket) -> str:
        """Calculate packet checksum for integrity"""
        checksum_data = (
            packet.packet_type.value.to_bytes(1, 'big') +
            packet.source_id.encode() +
            packet.destination_id.encode() +
            packet.session_id.encode() +
            packet.sequence_number.to_bytes(4, 'big') +
            packet.payload
        )
        
        return hashlib.sha256(checksum_data).hexdigest()[:16]
    
    def _packet_processor_worker(self):
        """Process incoming packets"""
        while self.is_listening:
            try:
                # Get packet from queue with timeout
                packet_info = self.packet_queue.get(timeout=1.0)
                packet, connection_info = packet_info
                
                # Verify packet integrity
                expected_checksum = self._calculate_packet_checksum(packet)
                if packet.checksum != expected_checksum:
                    self.logger.warning(f"Packet checksum mismatch from {packet.source_id}")
                    continue
                
                # Route to appropriate handler
                handler = self.message_handlers.get(packet.packet_type)
                if handler:
                    try:
                        handler(packet, connection_info)
                    except Exception as e:
                        self.logger.error(f"Error handling {packet.packet_type}: {e}")
                else:
                    self.logger.warning(f"No handler for packet type {packet.packet_type}")
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Packet processor error: {e}")
    
    def _packet_sender_worker(self):
        """Process outbound packet queue"""
        while self.is_listening:
            try:
                # Get packet from outbound queue
                packet_info = self.outbound_queue.get(timeout=1.0)
                packet, destination = packet_info
                
                # Send packet
                self._send_packet(packet, destination)
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Packet sender error: {e}")
    
    def _session_maintenance_worker(self):
        """Maintain active sessions (heartbeat, timeouts, cleanup)"""
        while self.is_listening:
            try:
                current_time = datetime.now()
                sessions_to_remove = []
                
                with self.session_lock:
                    for session_id, session_info in self.active_sessions.items():
                        # Check for session timeout
                        inactive_time = (current_time - session_info.last_activity).total_seconds()
                        
                        if inactive_time > self.config['session_timeout']:
                            sessions_to_remove.append(session_id)
                            continue
                        
                        # Send heartbeat if needed
                        if (session_info.state == SessionState.ESTABLISHED and
                            inactive_time > self.config['heartbeat_interval']):
                            
                            self._send_heartbeat(session_id)
                        
                        # Check for key rotation threshold
                        bytes_sent = session_info.network_stats.get('bytes_sent', 0)
                        if bytes_sent > self.config['key_rotation_threshold']:
                            self._initiate_key_rotation(session_id)
                
                # Remove timed out sessions
                for session_id in sessions_to_remove:
                    self.terminate_session(session_id, reason="timeout")
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Session maintenance error: {e}")
    
    def _handle_handshake_init(self, packet: NetworkPacket, connection_info):
        """Handle handshake initialization"""
        try:
            # Parse payload
            payload_parts = packet.payload.split(b'|HMAC|')
            if len(payload_parts) != 2:
                self.logger.warning("Invalid handshake init payload format")
                return
            
            payload_json, received_mac = payload_parts
            handshake_data = json.loads(payload_json.decode('utf-8'))
            
            # Verify HMAC (simplified - in real implementation, would derive shared key)
            # For now, we'll skip HMAC verification in simulation mode
            
            # Create session
            session_info = SessionInfo(
                session_id=packet.session_id,
                peer_device_id=packet.source_id,
                state=SessionState.HANDSHAKE_RESPONDING,
                created_at=datetime.now(),
                last_activity=datetime.now(),
                tensor_key_id="",
                ai_logic_data=None,
                dictionary_id="",
                sequence_number=1,
                peer_sequence=packet.sequence_number,
                encryption_params=handshake_data.get('device_capabilities', {}),
                network_stats=defaultdict(int)
            )
            
            # Store session
            with self.session_lock:
                self.active_sessions[packet.session_id] = session_info
                self.peer_sessions[packet.source_id] = packet.session_id
            
            # Generate cryptographic components
            self._setup_session_crypto(packet.session_id, packet.source_id)
            
            # Send handshake response
            self._send_handshake_response(packet.session_id, packet.source_id)
            
            self.logger.info(f"Responding to handshake from {packet.source_id}")
            
        except Exception as e:
            self.logger.error(f"Error handling handshake init: {e}")
            self._send_error_packet(packet.source_id, packet.session_id, "handshake_failed")
    
    def _handle_handshake_response(self, packet: NetworkPacket, connection_info):
        """Handle handshake response"""
        try:
            with self.session_lock:
                session_info = self.active_sessions.get(packet.session_id)
                if not session_info or session_info.state != SessionState.HANDSHAKE_INITIATED:
                    self.logger.warning(f"Invalid handshake response for session {packet.session_id}")
                    return
                
                # Update session state
                session_info.state = SessionState.ESTABLISHED
                session_info.last_activity = datetime.now()
                session_info.peer_sequence = packet.sequence_number
            
            # Setup cryptographic components if not already done
            if not session_info.tensor_key_id:
                self._setup_session_crypto(packet.session_id, packet.source_id)
            
            # Send handshake completion
            self._send_handshake_complete(packet.session_id, packet.source_id)
            
            self.metrics['handshakes_completed'] += 1
            self.metrics['sessions_established'] += 1
            
            self.logger.info(f"Handshake completed with {packet.source_id}")
            
        except Exception as e:
            self.logger.error(f"Error handling handshake response: {e}")
    
    def _handle_handshake_complete(self, packet: NetworkPacket, connection_info):
        """Handle handshake completion"""
        try:
            with self.session_lock:
                session_info = self.active_sessions.get(packet.session_id)
                if not session_info:
                    return
                
                session_info.state = SessionState.ESTABLISHED
                session_info.last_activity = datetime.now()
                session_info.peer_sequence = packet.sequence_number
            
            self.metrics['handshakes_completed'] += 1
            self.metrics['sessions_established'] += 1
            
            self.logger.info(f"Session established with {packet.source_id}")
            
        except Exception as e:
            self.logger.error(f"Error handling handshake complete: {e}")
    
    def _setup_session_crypto(self, session_id: str, peer_device_id: str):
        """Setup cryptographic components for session"""
        with self.session_lock:
            session_info = self.active_sessions.get(session_id)
            if not session_info:
                return
            
            try:
                # Generate tensor key
                tensor_key_id, tensor_key = self.key_manager.derive_key(
                    KeyType.TENSOR, 
                    f'session_tensor_{session_id}',
                    session_id=session_id
                )
                session_info.tensor_key_id = tensor_key_id
                
                # Generate AI logic
                ai_logic, ai_metadata = self.ai_logic.generate_session_logic(
                    session_id, peer_device_id
                )
                session_info.ai_logic_data = ai_logic
                
                # Generate shared dictionary
                dict_id, dictionary = self.dict_manager.generate_shared_dictionary(
                    peer_device_id, session_id
                )
                session_info.dictionary_id = dict_id
                
                self.logger.debug(f"Crypto setup completed for session {session_id[:16]}...")
                
            except Exception as e:
                self.logger.error(f"Failed to setup session crypto: {e}")
                session_info.state = SessionState.ERROR
    
    def _send_handshake_response(self, session_id: str, peer_device_id: str):
        """Send handshake response packet"""
        response_data = {
            'status': 'accepted',
            'device_capabilities': {
                'tensor_dimensions': self.tensor_engine.tensor_dims,
                'security_level': self.tensor_engine.security_level
            },
            'timestamp': time.time()
        }
        
        payload = json.dumps(response_data).encode('utf-8')
        
        with self.session_lock:
            session_info = self.active_sessions[session_id]
            
            packet = NetworkPacket(
                packet_type=PacketType.HANDSHAKE_RESPONSE,
                source_id=self.device_id,
                destination_id=peer_device_id,
                session_id=session_id,
                sequence_number=session_info.sequence_number,
                payload=payload,
                timestamp=time.time(),
                checksum=""
            )
            
            packet.checksum = self._calculate_packet_checksum(packet)
            session_info.sequence_number += 1
        
        # Queue for sending
        self.outbound_queue.put((packet, None))
    
    def _send_handshake_complete(self, session_id: str, peer_device_id: str):
        """Send handshake completion packet"""
        complete_data = {
            'status': 'established',
            'timestamp': time.time()
        }
        
        payload = json.dumps(complete_data).encode('utf-8')
        
        with self.session_lock:
            session_info = self.active_sessions[session_id]
            
            packet = NetworkPacket(
                packet_type=PacketType.HANDSHAKE_COMPLETE,
                source_id=self.device_id,
                destination_id=peer_device_id,
                session_id=session_id,
                sequence_number=session_info.sequence_number,
                payload=payload,
                timestamp=time.time(),
                checksum=""
            )
            
            packet.checksum = self._calculate_packet_checksum(packet)
            session_info.sequence_number += 1
        
        self.outbound_queue.put((packet, None))
    
    def send_encrypted_data(self, session_id: str, data: bytes) -> bool:
        """
        Send encrypted data through established session
        
        Args:
            session_id: Session to send data through
            data: Data to encrypt and send
            
        Returns:
            Success status
        """
        with self.session_lock:
            session_info = self.active_sessions.get(session_id)
            if not session_info or session_info.state != SessionState.ESTABLISHED:
                return False
            
            try:
                # Get session tensor key
                tensor_key = self.key_manager.get_key(session_info.tensor_key_id)
                
                # Reshape tensor key for encryption
                tensor_key_reshaped = np.frombuffer(tensor_key, dtype=np.uint8)
                tensor_key_reshaped = tensor_key_reshaped[:np.prod(self.tensor_engine.tensor_dims)]
                tensor_key_reshaped = tensor_key_reshaped.reshape(self.tensor_engine.tensor_dims)
                
                # Encrypt data
                encrypted_data, metadata = self.tensor_engine.encrypt_data(
                    data, tensor_key_reshaped
                )
                
                # Enhance with AI logic
                if session_info.ai_logic_data is not None:
                    ai_logic_tensor = session_info.ai_logic_data.reshape(self.tensor_engine.tensor_dims)
                    # Additional XOR with AI logic (simplified)
                    encrypted_enhanced = np.bitwise_xor(
                        np.frombuffer(encrypted_data, dtype=np.uint8)[:len(encrypted_data)],
                        np.tile(ai_logic_tensor.flatten().astype(np.uint8), 
                               (len(encrypted_data) // ai_logic_tensor.size) + 1)[:len(encrypted_data)]
                    )
                    encrypted_data = encrypted_enhanced.tobytes()
                
                # Create encrypted packet
                packet = NetworkPacket(
                    packet_type=PacketType.DATA_ENCRYPTED,
                    source_id=self.device_id,
                    destination_id=session_info.peer_device_id,
                    session_id=session_id,
                    sequence_number=session_info.sequence_number,
                    payload=encrypted_data,
                    timestamp=time.time(),
                    checksum=""
                )
                
                packet.checksum = self._calculate_packet_checksum(packet)
                
                # Update session stats
                session_info.sequence_number += 1
                session_info.last_activity = datetime.now()
                session_info.network_stats['bytes_sent'] += len(encrypted_data)
                
                # Queue for sending
                self.outbound_queue.put((packet, None))
                
                self.metrics['encryption_operations'] += 1
                
                return True
                
            except Exception as e:
                self.logger.error(f"Failed to send encrypted data: {e}")
                return False
    
    def _handle_encrypted_data(self, packet: NetworkPacket, connection_info):
        """Handle encrypted data packet"""
        try:
            with self.session_lock:
                session_info = self.active_sessions.get(packet.session_id)
                if not session_info or session_info.state != SessionState.ESTABLISHED:
                    return
                
                # Get decryption key
                tensor_key = self.key_manager.get_key(session_info.tensor_key_id)
                tensor_key_reshaped = np.frombuffer(tensor_key, dtype=np.uint8)
                tensor_key_reshaped = tensor_key_reshaped[:np.prod(self.tensor_engine.tensor_dims)]
                tensor_key_reshaped = tensor_key_reshaped.reshape(self.tensor_engine.tensor_dims)
                
                encrypted_data = packet.payload
                
                # Reverse AI logic enhancement
                if session_info.ai_logic_data is not None:
                    ai_logic_tensor = session_info.ai_logic_data.reshape(self.tensor_engine.tensor_dims)
                    encrypted_original = np.bitwise_xor(
                        np.frombuffer(encrypted_data, dtype=np.uint8),
                        np.tile(ai_logic_tensor.flatten().astype(np.uint8), 
                               (len(encrypted_data) // ai_logic_tensor.size) + 1)[:len(encrypted_data)]
                    )
                    encrypted_data = encrypted_original.tobytes()
                
                # Decrypt data
                # Create minimal metadata for decryption
                decrypt_metadata = {
                    'nonce': os.urandom(16),  # Simplified - should be from encryption
                    'original_length': len(encrypted_data),
                    'tensor_hash': hashlib.sha256(tensor_key_reshaped.tobytes()).hexdigest(),
                    'tensor_dimensions': self.tensor_engine.tensor_dims
                }
                
                # For demo purposes, we'll simulate decryption
                # In real implementation, this would use proper metadata
                decrypted_data = self._simulate_decrypt(encrypted_data, tensor_key_reshaped)
                
                # Update session stats
                session_info.last_activity = datetime.now()
                session_info.peer_sequence = packet.sequence_number
                session_info.network_stats['bytes_received'] += len(encrypted_data)
                
                self.metrics['decryption_operations'] += 1
                
                # Process decrypted data (could trigger callbacks)
                self._process_decrypted_data(packet.session_id, decrypted_data)
                
        except Exception as e:
            self.logger.error(f"Failed to handle encrypted data: {e}")
    
    def _simulate_decrypt(self, encrypted_data: bytes, tensor_key: np.ndarray) -> bytes:
        """Simulate decryption for demo purposes"""
        # This is a simplified decryption simulation
        # In real implementation, would use proper tensor decryption
        data_array = np.frombuffer(encrypted_data, dtype=np.uint8)
        key_pattern = np.tile(tensor_key.flatten().astype(np.uint8), 
                             (len(data_array) // tensor_key.size) + 1)[:len(data_array)]
        decrypted_array = np.bitwise_xor(data_array, key_pattern)
        return decrypted_array.tobytes()
    
    def _process_decrypted_data(self, session_id: str, data: bytes):
        """Process successfully decrypted data"""
        # In a real implementation, this would route data to appropriate handlers
        self.logger.debug(f"Received {len(data)} bytes of decrypted data in session {session_id[:16]}...")
    
    def _handle_heartbeat(self, packet: NetworkPacket, connection_info):
        """Handle heartbeat packet"""
        with self.session_lock:
            session_info = self.active_sessions.get(packet.session_id)
            if session_info:
                session_info.last_activity = datetime.now()
                session_info.peer_sequence = packet.sequence_number
    
    def _send_heartbeat(self, session_id: str):
        """Send heartbeat packet"""
        with self.session_lock:
            session_info = self.active_sessions.get(session_id)
            if not session_info:
                return
            
            packet = NetworkPacket(
                packet_type=PacketType.HEARTBEAT,
                source_id=self.device_id,
                destination_id=session_info.peer_device_id,
                session_id=session_id,
                sequence_number=session_info.sequence_number,
                payload=b'ping',
                timestamp=time.time(),
                checksum=""
            )
            
            packet.checksum = self._calculate_packet_checksum(packet)
            session_info.sequence_number += 1
            session_info.last_activity = datetime.now()
        
        self.outbound_queue.put((packet, None))
    
    def _handle_key_rotation(self, packet: NetworkPacket, connection_info):
        """Handle key rotation packet"""
        # Implementation for handling key rotation requests
        pass
    
    def _handle_dictionary_sync(self, packet: NetworkPacket, connection_info):
        """Handle dictionary synchronization packet"""
        # Implementation for dictionary sync
        pass
    
    def _handle_error(self, packet: NetworkPacket, connection_info):
        """Handle error packet"""
        self.logger.warning(f"Received error from {packet.source_id}: {packet.payload.decode('utf-8')}")
    
    def _handle_disconnect(self, packet: NetworkPacket, connection_info):
        """Handle disconnect packet"""
        self.terminate_session(packet.session_id, reason="peer_disconnect")
    
    def _send_error_packet(self, destination: str, session_id: str, error_message: str):
        """Send error packet"""
        packet = NetworkPacket(
            packet_type=PacketType.ERROR,
            source_id=self.device_id,
            destination_id=destination,
            session_id=session_id,
            sequence_number=0,
            payload=error_message.encode('utf-8'),
            timestamp=time.time(),
            checksum=""
        )
        
        packet.checksum = self._calculate_packet_checksum(packet)
        self.outbound_queue.put((packet, None))
    
    def _initiate_key_rotation(self, session_id: str):
        """Initiate key rotation for session"""
        # Implementation for initiating key rotation
        with self.session_lock:
            session_info = self.active_sessions.get(session_id)
            if session_info:
                session_info.state = SessionState.KEY_ROTATING
                # Reset byte counter
                session_info.network_stats['bytes_sent'] = 0
                self.metrics['key_rotations'] += 1
    
    def terminate_session(self, session_id: str, reason: str = "manual"):
        """
        Terminate active session
        
        Args:
            session_id: Session to terminate
            reason: Reason for termination
        """
        with self.session_lock:
            session_info = self.active_sessions.get(session_id)
            if not session_info:
                return
            
            # Send disconnect packet
            if session_info.state != SessionState.ERROR:
                disconnect_packet = NetworkPacket(
                    packet_type=PacketType.DISCONNECT,
                    source_id=self.device_id,
                    destination_id=session_info.peer_device_id,
                    session_id=session_id,
                    sequence_number=session_info.sequence_number,
                    payload=reason.encode('utf-8'),
                    timestamp=time.time(),
                    checksum=""
                )
                
                disconnect_packet.checksum = self._calculate_packet_checksum(disconnect_packet)
                self.outbound_queue.put((disconnect_packet, None))
            
            # Clean up session
            peer_device_id = session_info.peer_device_id
            
            del self.active_sessions[session_id]
            if peer_device_id in self.peer_sessions:
                del self.peer_sessions[peer_device_id]
            
            self.logger.info(f"Session {session_id[:16]}... terminated ({reason})")
    
    def get_session_info(self, session_id: str) -> Optional[SessionInfo]:
        """Get session information"""
        with self.session_lock:
            return self.active_sessions.get(session_id)
    
    def list_active_sessions(self) -> List[SessionInfo]:
        """List all active sessions"""
        with self.session_lock:
            return list(self.active_sessions.values())
    
    def connect_simulation_peer(self, peer_interface: 'RouterInterface'):
        """Connect to peer in simulation mode"""
        if self.protocol == NetworkProtocol.SIMULATION:
            self.simulation_network[peer_interface.device_id] = peer_interface
            peer_interface.simulation_network[self.device_id] = self
            self.logger.info(f"Connected to simulation peer {peer_interface.device_id}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get router interface metrics"""
        with self.session_lock:
            return {
                **self.metrics,
                'active_sessions': len(self.active_sessions),
                'is_listening': self.is_listening,
                'protocol': self.protocol.value,
                'listen_port': self.listen_port,
                'queue_sizes': {
                    'inbound': self.packet_queue.qsize(),
                    'outbound': self.outbound_queue.qsize()
                }
            }
    
    def __repr__(self) -> str:
        """String representation"""
        return (f"RouterInterface(device_id='{self.device_id}', "
                f"protocol={self.protocol.value}, "
                f"sessions={len(self.active_sessions)}, "
                f"listening={self.is_listening})")
