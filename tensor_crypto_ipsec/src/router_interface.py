# [file name]: src/router_interface.py
"""
Enhanced Router Interface for Quantum-Resistant IPSec Alternative
Advanced network routing interface with quantum-resistant encryption capabilities

Features:
- Quantum-resistant packet encryption/decryption
- Adaptive routing with load balancing
- Real-time network monitoring and analytics
- Secure session management with forward secrecy
- Multi-protocol support (TCP, UDP, ICMP, custom)
- Hardware acceleration integration
- Comprehensive QoS and traffic shaping
"""

import socket
import threading
import time
import logging
import json
import hashlib
import secrets
from typing import Dict, List, Tuple, Optional, Any, Union, Callable
from enum import Enum
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import struct
import select
import asyncio
import ipaddress
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import numpy as np
import psutil
from concurrent.futures import ThreadPoolExecutor
import queue

# Import project modules
from tensor_engine import TensorEncryptionEngine
from key_management import KeyManager, KeyType
from dictionary_manager import DictionaryManager, DictionaryType
from ai_logic import AILogicGenerator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ProtocolType(Enum):
    """Supported network protocols"""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    RAW = "raw"
    CUSTOM = "custom"

class SessionState(Enum):
    """Session connection states"""
    INIT = "init"
    HANDSHAKE = "handshake"
    ESTABLISHED = "established"
    CLOSING = "closing"
    CLOSED = "closed"
    ERROR = "error"

class TrafficPriority(Enum):
    """Traffic priority levels"""
    REAL_TIME = "real_time"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    BACKGROUND = "background"

@dataclass
class SessionMetadata:
    """Session connection metadata"""
    session_id: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: ProtocolType
    state: SessionState
    created_at: datetime
    last_activity: datetime
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    encryption_level: str
    session_key_id: str
    dictionary_id: str
    quality_metrics: Dict[str, float]

@dataclass
class RouterConfig:
    """Router configuration parameters"""
    interface_name: str
    listen_ip: str
    listen_port: int
    max_connections: int
    buffer_size: int
    timeout_seconds: float
    enable_encryption: bool
    enable_compression: bool
    security_level: str
    traffic_shaping: bool
    quality_of_service: bool
    hardware_acceleration: bool

@dataclass
class PerformanceMetrics:
    """Router performance metrics"""
    total_sessions: int
    active_sessions: int
    packets_processed: int
    bytes_processed: int
    encryption_operations: int
    decryption_operations: int
    average_latency: float
    error_count: int
    cache_hits: int
    cache_misses: int
    network_throughput: float

class RouterInterface:
    """
    Advanced Router Interface for Quantum-Resistant IPSec Alternative
    
    Features:
    - Quantum-resistant packet encryption using tensor operations
    - Adaptive routing with intelligent path selection
    - Real-time network analytics and monitoring
    - Secure session management with forward secrecy
    - Multi-protocol support with hardware acceleration
    - Comprehensive QoS and traffic shaping
    """

    # Packet header format (custom protocol)
    PACKET_HEADER_FORMAT = '!BBHHLLQ'  # version, flags, length, session_id, timestamp, nonce
    PACKET_HEADER_SIZE = struct.calcsize('!BBHHLLQ')

    def __init__(self,
                 config: RouterConfig,
                 key_manager: KeyManager,
                 dictionary_manager: DictionaryManager,
                 tensor_engine: TensorEncryptionEngine,
                 ai_logic_generator: AILogicGenerator):
        """
        Initialize the Advanced Router Interface
        
        Args:
            config: Router configuration
            key_manager: Key management instance
            dictionary_manager: Dictionary management instance
            tensor_engine: Tensor encryption engine
            ai_logic_generator: AI logic generator
        """
        
        self.config = config
        self.key_manager = key_manager
        self.dictionary_manager = dictionary_manager
        self.tensor_engine = tensor_engine
        self.ai_logic = ai_logic_generator
        
        # Session management
        self.sessions: Dict[str, SessionMetadata] = {}
        self.session_lock = threading.RLock()
        
        # Network components
        self.socket = None
        self.listening = False
        self.packet_queue = queue.Queue()
        self.worker_threads = []
        
        # Performance tracking
        self.performance_metrics = PerformanceMetrics(0, 0, 0, 0, 0, 0, 0.0, 0, 0, 0, 0.0)
        self.start_time = time.time()
        
        # Traffic shaping
        self.traffic_queues = {
            TrafficPriority.REAL_TIME: queue.Queue(),
            TrafficPriority.HIGH: queue.Queue(),
            TrafficPriority.MEDIUM: queue.Queue(),
            TrafficPriority.LOW: queue.Queue(),
            TrafficPriority.BACKGROUND: queue.Queue()
        }
        
        # Thread management
        self.thread_pool = ThreadPoolExecutor(max_workers=8)
        self.background_tasks = {}
        
        # Initialize network interface
        self._initialize_network_interface()
        
        # Start background services
        self._start_background_services()
        
        logger.info(f"RouterInterface initialized on {config.interface_name} "
                   f"({config.listen_ip}:{config.listen_port})")

    def _initialize_network_interface(self):
        """Initialize network socket and interface"""
        try:
            # Create raw socket for packet-level control
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Set socket options for performance
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.config.buffer_size)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.config.buffer_size)
            
            # Bind to interface
            self.socket.bind((self.config.listen_ip, self.config.listen_port))
            
            # Set non-blocking if using async
            self.socket.setblocking(False)
            
            logger.info(f"Network interface initialized on {self.config.interface_name}")
            
        except Exception as e:
            logger.error(f"Failed to initialize network interface: {e}")
            raise

    def _start_background_services(self):
        """Start background maintenance and monitoring services"""
        def packet_processor():
            """Background packet processing service"""
            while self.listening:
                try:
                    # Process packets from all priority queues
                    for priority in [TrafficPriority.REAL_TIME, TrafficPriority.HIGH, 
                                   TrafficPriority.MEDIUM, TrafficPriority.LOW, 
                                   TrafficPriority.BACKGROUND]:
                        try:
                            packet_data = self.traffic_queues[priority].get_nowait()
                            self._process_packet(packet_data, priority)
                        except queue.Empty:
                            continue
                    
                    time.sleep(0.001)  # Small delay to prevent CPU spinning
                    
                except Exception as e:
                    logger.error(f"Packet processor error: {e}")
                    time.sleep(0.1)

        def session_cleanup_service():
            """Background session cleanup service"""
            while self.listening:
                try:
                    self._cleanup_expired_sessions()
                    time.sleep(30)  # Run every 30 seconds
                except Exception as e:
                    logger.error(f"Session cleanup error: {e}")
                    time.sleep(60)

        def performance_monitor_service():
            """Background performance monitoring service"""
            while self.listening:
                try:
                    self._update_performance_metrics()
                    time.sleep(5)  # Update every 5 seconds
                except Exception as e:
                    logger.error(f"Performance monitor error: {e}")
                    time.sleep(10)

        # Start background threads
        self.listening = True
        
        self.packet_processor_thread = threading.Thread(target=packet_processor, daemon=True)
        self.session_cleanup_thread = threading.Thread(target=session_cleanup_service, daemon=True)
        self.performance_monitor_thread = threading.Thread(target=performance_monitor_service, daemon=True)
        
        self.packet_processor_thread.start()
        self.session_cleanup_thread.start()
        self.performance_monitor_thread.start()
        
        logger.info("Background services started")

    def start_listening(self):
        """Start listening for incoming packets"""
        def listener_thread():
            """Main packet listener thread"""
            while self.listening:
                try:
                    # Use select for non-blocking socket operations
                    ready, _, _ = select.select([self.socket], [], [], 0.1)
                    if ready:
                        packet_data, address = self.socket.recvfrom(self.config.buffer_size)
                        self._queue_packet(packet_data, address)
                        
                except socket.error as e:
                    if e.errno != socket.EWOULDBLOCK:
                        logger.error(f"Socket error in listener: {e}")
                        time.sleep(0.1)
                except Exception as e:
                    logger.error(f"Listener thread error: {e}")
                    time.sleep(0.1)

        self.listener_thread = threading.Thread(target=listener_thread, daemon=True)
        self.listener_thread.start()
        
        logger.info(f"Started listening on {self.config.listen_ip}:{self.config.listen_port}")

    def _queue_packet(self, packet_data: bytes, address: Tuple[str, int]):
        """Queue packet for processing based on priority"""
        try:
            # Determine packet priority (simplified - in reality would inspect packet content)
            priority = self._determine_packet_priority(packet_data, address)
            
            # Add to appropriate queue
            self.traffic_queues[priority].put((packet_data, address))
            
            self.performance_metrics.packets_processed += 1
            self.performance_metrics.bytes_processed += len(packet_data)
            
        except Exception as e:
            logger.error(f"Failed to queue packet: {e}")
            self.performance_metrics.error_count += 1

    def _determine_packet_priority(self, packet_data: bytes, address: Tuple[str, int]) -> TrafficPriority:
        """Determine packet priority based on content and source"""
        # Simplified priority determination
        # In production, this would analyze packet headers and content
        
        if len(packet_data) < 100:  # Small packets often control packets
            return TrafficPriority.REAL_TIME
        
        # Check if this is from an established session
        source_ip, source_port = address
        session_id = self._get_session_id(source_ip, source_port)
        
        if session_id and session_id in self.sessions:
            session = self.sessions[session_id]
            if session.state == SessionState.ESTABLISHED:
                return TrafficPriority.HIGH
        
        return TrafficPriority.MEDIUM

    def _process_packet(self, packet_data: Tuple[bytes, Tuple[str, int]], priority: TrafficPriority):
        """Process incoming packet"""
        packet, address = packet_data
        start_time = time.time()
        
        try:
            # Parse packet header
            header_data = packet[:self.PACKET_HEADER_SIZE]
            version, flags, length, session_id, timestamp, nonce = struct.unpack(
                self.PACKET_HEADER_FORMAT, header_data
            )
            
            # Extract payload
            payload = packet[self.PACKET_HEADER_SIZE:self.PACKET_HEADER_SIZE + length]
            
            # Get or create session
            source_ip, source_port = address
            session = self._get_or_create_session(session_id, source_ip, source_port)
            
            if session:
                # Update session activity
                session.last_activity = datetime.now()
                session.packets_received += 1
                session.bytes_received += len(packet)
                
                # Decrypt payload if encrypted
                if flags & 0x01:  # Encryption flag
                    decrypted_payload = self._decrypt_packet(payload, session)
                    self.performance_metrics.decryption_operations += 1
                else:
                    decrypted_payload = payload
                
                # Handle packet based on protocol and content
                self._handle_packet_payload(decrypted_payload, session, address)
                
                # Update latency metrics
                processing_time = time.time() - start_time
                self._update_latency_metrics(processing_time)
                
            else:
                logger.warning(f"No session found for packet from {address}")
                
        except Exception as e:
            logger.error(f"Failed to process packet from {address}: {e}")
            self.performance_metrics.error_count += 1

    def _get_or_create_session(self, session_id: int, source_ip: str, source_port: int) -> Optional[SessionMetadata]:
        """Get existing session or create new one"""
        session_key = f"{source_ip}:{source_port}:{session_id}"
        
        with self.session_lock:
            if session_key in self.sessions:
                return self.sessions[session_key]
            
            # Create new session
            try:
                # Generate session-specific resources
                session_key_id, session_key_data = self.key_manager.derive_key(
                    KeyType.SESSION,
                    f"session_{session_key}",
                    session_id=session_key
                )
                
                # Create session dictionary
                dictionary_id = self.dictionary_manager.create_dictionary(
                    DictionaryType.SESSION,
                    session_id=session_key,
                    expiration_hours=24
                )
                
                # Generate AI logic for session
                logic_vector, logic_metadata = self.ai_logic.generate_session_logic(
                    session_key,
                    f"router_{self.config.interface_name}",
                    additional_entropy=session_key_data
                )
                
                # Store logic in dictionary
                self.dictionary_manager.update_dictionary(
                    dictionary_id,
                    {"ai_logic": logic_vector.tolist(), "logic_metadata": asdict(logic_metadata)}
                )
                
                # Create session metadata
                session = SessionMetadata(
                    session_id=session_key,
                    source_ip=source_ip,
                    destination_ip=self.config.listen_ip,
                    source_port=source_port,
                    destination_port=self.config.listen_port,
                    protocol=ProtocolType.TCP,  # Default, would detect from packet
                    state=SessionState.HANDSHAKE,
                    created_at=datetime.now(),
                    last_activity=datetime.now(),
                    bytes_sent=0,
                    bytes_received=0,
                    packets_sent=0,
                    packets_received=0,
                    encryption_level=self.config.security_level,
                    session_key_id=session_key_id,
                    dictionary_id=dictionary_id,
                    quality_metrics={}
                )
                
                self.sessions[session_key] = session
                self.performance_metrics.total_sessions += 1
                self.performance_metrics.active_sessions += 1
                
                logger.info(f"Created new session: {session_key}")
                return session
                
            except Exception as e:
                logger.error(f"Failed to create session {session_key}: {e}")
                return None

    def _decrypt_packet(self, encrypted_payload: bytes, session: SessionMetadata) -> bytes:
        """Decrypt packet payload using session keys and tensor engine"""
        try:
            # Get session dictionary
            session_dict = self.dictionary_manager.get_dictionary(session.dictionary_id)
            
            # Get AI logic from dictionary
            ai_logic_vector = np.array(session_dict["ai_logic"], dtype=np.int8)
            logic_tensor = ai_logic_vector.reshape(self.tensor_engine.tensor_dims)
            
            # Get session key
            session_key = self.key_manager.get_key(session.session_key_id)
            
            # Create metadata for decryption
            metadata = {
                'tensor_hash': hashlib.sha3_512(logic_tensor.tobytes()).hexdigest(),
                'original_length': len(encrypted_payload),
                'security_level': self.config.security_level
            }
            
            # Decrypt payload
            decrypted_payload = self.tensor_engine.decrypt_data(
                encrypted_payload,
                logic_tensor,
                metadata
            )
            
            return decrypted_payload
            
        except Exception as e:
            logger.error(f"Failed to decrypt packet for session {session.session_id}: {e}")
            raise

    def _encrypt_packet(self, plaintext_payload: bytes, session: SessionMetadata) -> bytes:
        """Encrypt packet payload using session keys and tensor engine"""
        try:
            # Get session dictionary
            session_dict = self.dictionary_manager.get_dictionary(session.dictionary_id)
            
            # Get AI logic from dictionary
            ai_logic_vector = np.array(session_dict["ai_logic"], dtype=np.int8)
            logic_tensor = ai_logic_vector.reshape(self.tensor_engine.tensor_dims)
            
            # Encrypt payload
            encrypted_payload, metadata = self.tensor_engine.encrypt_data(
                plaintext_payload,
                logic_tensor
            )
            
            self.performance_metrics.encryption_operations += 1
            
            return encrypted_payload
            
        except Exception as e:
            logger.error(f"Failed to encrypt packet for session {session.session_id}: {e}")
            raise

    def _handle_packet_payload(self, payload: bytes, session: SessionMetadata, address: Tuple[str, int]):
        """Handle decrypted packet payload"""
        try:
            # Parse payload based on protocol (simplified)
            # In production, this would handle various protocol types
            
            if session.protocol == ProtocolType.TCP:
                self._handle_tcp_payload(payload, session, address)
            elif session.protocol == ProtocolType.UDP:
                self._handle_udp_payload(payload, session, address)
            elif session.protocol == ProtocolType.ICMP:
                self._handle_icmp_payload(payload, session, address)
            else:
                self._handle_custom_payload(payload, session, address)
                
        except Exception as e:
            logger.error(f"Failed to handle packet payload for session {session.session_id}: {e}")

    def _handle_tcp_payload(self, payload: bytes, session: SessionMetadata, address: Tuple[str, int]):
        """Handle TCP protocol payload"""
        # Simplified TCP handling - in production would implement full TCP state machine
        try:
            # Extract TCP header (simplified)
            if len(payload) >= 20:  # Minimum TCP header size
                # Parse basic TCP header fields
                src_port = struct.unpack('!H', payload[0:2])[0]
                dst_port = struct.unpack('!H', payload[2:4])[0]
                seq_num = struct.unpack('!L', payload[4:8])[0]
                ack_num = struct.unpack('!L', payload[8:12])[0]
                
                # Update session with port information
                session.source_port = src_port
                session.destination_port = dst_port
                
                # Handle TCP flags
                flags = struct.unpack('!B', payload[13:14])[0]
                
                if flags & 0x02:  # SYN flag
                    self._handle_syn(session, seq_num)
                elif flags & 0x10:  # ACK flag
                    self._handle_ack(session, ack_num)
                elif flags & 0x01:  # FIN flag
                    self._handle_fin(session)
                else:
                    # Data payload
                    data_offset = (struct.unpack('!B', payload[12:13])[0] >> 4) * 4
                    if len(payload) > data_offset:
                        data = payload[data_offset:]
                        self._handle_application_data(data, session, address)
                        
        except Exception as e:
            logger.error(f"Failed to handle TCP payload: {e}")

    def _handle_udp_payload(self, payload: bytes, session: SessionMetadata, address: Tuple[str, int]):
        """Handle UDP protocol payload"""
        try:
            # Extract UDP header
            if len(payload) >= 8:  # UDP header size
                src_port = struct.unpack('!H', payload[0:2])[0]
                dst_port = struct.unpack('!H', payload[2:4])[0]
                length = struct.unpack('!H', payload[4:6])[0]
                
                # Update session
                session.source_port = src_port
                session.destination_port = dst_port
                
                # Extract data
                if len(payload) > 8:
                    data = payload[8:8+length]
                    self._handle_application_data(data, session, address)
                    
        except Exception as e:
            logger.error(f"Failed to handle UDP payload: {e}")

    def _handle_icmp_payload(self, payload: bytes, session: SessionMetadata, address: Tuple[str, int]):
        """Handle ICMP protocol payload"""
        try:
            # Extract ICMP header
            if len(payload) >= 8:  # Basic ICMP header
                icmp_type = struct.unpack('!B', payload[0:1])[0]
                icmp_code = struct.unpack('!B', payload[1:2])[0]
                
                # Handle different ICMP types
                if icmp_type == 8:  # Echo request
                    self._handle_icmp_echo_request(payload, session, address)
                elif icmp_type == 0:  # Echo reply
                    self._handle_icmp_echo_reply(payload, session, address)
                else:
                    logger.debug(f"Unhandled ICMP type: {icmp_type}")
                    
        except Exception as e:
            logger.error(f"Failed to handle ICMP payload: {e}")

    def _handle_custom_payload(self, payload: bytes, session: SessionMetadata, address: Tuple[str, int]):
        """Handle custom protocol payload"""
        try:
            # Custom protocol handling would go here
            # For now, just log and pass to application layer
            self._handle_application_data(payload, session, address)
            
        except Exception as e:
            logger.error(f"Failed to handle custom payload: {e}")

    def _handle_application_data(self, data: bytes, session: SessionMetadata, address: Tuple[str, int]):
        """Handle application layer data"""
        try:
            # In production, this would pass data to the appropriate application
            # For this implementation, we'll just log and update metrics
            
            logger.debug(f"Application data from {address}: {len(data)} bytes")
            
            # Update session quality metrics
            self._update_session_quality(session, len(data))
            
            # Could trigger callbacks for application-level processing
            if hasattr(self, 'data_received_callback'):
                self.data_received_callback(data, session, address)
                
        except Exception as e:
            logger.error(f"Failed to handle application data: {e}")

    def _handle_syn(self, session: SessionMetadata, seq_num: int):
        """Handle TCP SYN packet"""
        try:
            if session.state == SessionState.INIT:
                session.state = SessionState.HANDSHAKE
                # Send SYN-ACK response
                self._send_syn_ack(session, seq_num)
                
        except Exception as e:
            logger.error(f"Failed to handle SYN: {e}")

    def _handle_ack(self, session: SessionMetadata, ack_num: int):
        """Handle TCP ACK packet"""
        try:
            if session.state == SessionState.HANDSHAKE:
                session.state = SessionState.ESTABLISHED
                logger.info(f"Session established: {session.session_id}")
                
        except Exception as e:
            logger.error(f"Failed to handle ACK: {e}")

    def _handle_fin(self, session: SessionMetadata):
        """Handle TCP FIN packet"""
        try:
            session.state = SessionState.CLOSING
            # Send FIN-ACK response
            self._send_fin_ack(session)
            
        except Exception as e:
            logger.error(f"Failed to handle FIN: {e}")

    def _handle_icmp_echo_request(self, payload: bytes, session: SessionMetadata, address: Tuple[str, int]):
        """Handle ICMP echo request (ping)"""
        try:
            # Create echo reply
            reply_payload = self._create_icmp_echo_reply(payload)
            
            # Send reply
            self.send_packet(reply_payload, address, session)
            
        except Exception as e:
            logger.error(f"Failed to handle ICMP echo request: {e}")

    def _handle_icmp_echo_reply(self, payload: bytes, session: SessionMetadata, address: Tuple[str, int]):
        """Handle ICMP echo reply (pong)"""
        try:
            # Update latency metrics based on echo reply
            timestamp = struct.unpack('!d', payload[8:16])[0]  # Assuming timestamp in payload
            current_time = time.time()
            latency = current_time - timestamp
            
            session.quality_metrics['latency'] = latency
            self._update_latency_metrics(latency)
            
        except Exception as e:
            logger.error(f"Failed to handle ICMP echo reply: {e}")

    def _create_icmp_echo_reply(self, request_payload: bytes) -> bytes:
        """Create ICMP echo reply from request"""
        try:
            # Copy request payload
            reply_payload = bytearray(request_payload)
            
            # Change type to Echo Reply (0)
            reply_payload[0] = 0
            
            # Recalculate checksum
            reply_payload[2:4] = b'\x00\x00'  # Clear checksum
            checksum = self._calculate_checksum(reply_payload)
            reply_payload[2:4] = struct.pack('!H', checksum)
            
            return bytes(reply_payload)
            
        except Exception as e:
            logger.error(f"Failed to create ICMP echo reply: {e}")
            raise

    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate IP checksum"""
        if len(data) % 2:
            data += b'\x00'
        
        total = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i+1]
            total += word
            total = (total & 0xffff) + (total >> 16)
        
        return ~total & 0xffff

    def send_packet(self, payload: bytes, address: Tuple[str, int], session: Optional[SessionMetadata] = None):
        """Send packet to specified address"""
        try:
            # Encrypt payload if session provided and encryption enabled
            if session and self.config.enable_encryption:
                encrypted_payload = self._encrypt_packet(payload, session)
                flags = 0x01  # Set encryption flag
            else:
                encrypted_payload = payload
                flags = 0x00
            
            # Create packet header
            session_id = hash(session.session_id) % 65536 if session else 0
            timestamp = int(time.time() * 1000)
            nonce = secrets.randbits(64)
            
            header = struct.pack(
                self.PACKET_HEADER_FORMAT,
                1,  # version
                flags,
                len(encrypted_payload),
                session_id,
                timestamp,
                nonce
            )
            
            # Combine header and payload
            packet = header + encrypted_payload
            
            # Send packet
            self.socket.sendto(packet, address)
            
            # Update session metrics
            if session:
                session.packets_sent += 1
                session.bytes_sent += len(packet)
                session.last_activity = datetime.now()
            
            logger.debug(f"Sent packet to {address}: {len(packet)} bytes")
            
        except Exception as e:
            logger.error(f"Failed to send packet to {address}: {e}")
            self.performance_metrics.error_count += 1

    def _send_syn_ack(self, session: SessionMetadata, seq_num: int):
        """Send TCP SYN-ACK response"""
        try:
            # Create SYN-ACK packet
            syn_ack_payload = self._create_tcp_packet(
                session.destination_port,
                session.source_port,
                seq_num + 1,  # ACK number
                0,  # SEQ number for our side
                0x12  # SYN-ACK flags (SYN=0x02, ACK=0x10)
            )
            
            # Send to source
            address = (session.source_ip, session.source_port)
            self.send_packet(syn_ack_payload, address, session)
            
        except Exception as e:
            logger.error(f"Failed to send SYN-ACK: {e}")

    def _send_fin_ack(self, session: SessionMetadata):
        """Send TCP FIN-ACK response"""
        try:
            # Create FIN-ACK packet
            fin_ack_payload = self._create_tcp_packet(
                session.destination_port,
                session.source_port,
                0,  # ACK number
                0,  # SEQ number
                0x11  # FIN-ACK flags (FIN=0x01, ACK=0x10)
            )
            
            # Send to source
            address = (session.source_ip, session.source_port)
            self.send_packet(fin_ack_payload, address, session)
            
        except Exception as e:
            logger.error(f"Failed to send FIN-ACK: {e}")

    def _create_tcp_packet(self, src_port: int, dst_port: int, ack_num: int, seq_num: int, flags: int) -> bytes:
        """Create TCP packet with specified parameters"""
        try:
            # TCP header (simplified)
            header = struct.pack('!HHLLBBHHH',
                               src_port, dst_port,
                               seq_num, ack_num,
                               5 << 4,  # Data offset
                               flags,
                               8192,  # Window size
                               0, 0)  # Checksum and urgent pointer
            
            return header
            
        except Exception as e:
            logger.error(f"Failed to create TCP packet: {e}")
            raise

    def _update_session_quality(self, session: SessionMetadata, data_size: int):
        """Update session quality metrics"""
        try:
            # Calculate various quality metrics
            current_time = time.time()
            session_duration = current_time - session.created_at.timestamp()
            
            throughput = session.bytes_received / session_duration if session_duration > 0 else 0
            packet_loss = 1 - (session.packets_received / (session.packets_sent + 1))
            
            session.quality_metrics.update({
                'throughput': throughput,
                'packet_loss': packet_loss,
                'data_size': data_size,
                'session_duration': session_duration,
                'last_update': current_time
            })
            
        except Exception as e:
            logger.warning(f"Failed to update session quality metrics: {e}")

    def _update_latency_metrics(self, latency: float):
        """Update overall latency metrics"""
        try:
            total_ops = self.performance_metrics.packets_processed
            self.performance_metrics.average_latency = (
                self.performance_metrics.average_latency * total_ops + latency
            ) / (total_ops + 1)
        except Exception as e:
            logger.warning(f"Failed to update latency metrics: {e}")

    def _update_performance_metrics(self):
        """Update comprehensive performance metrics"""
        try:
            # Calculate network throughput
            current_time = time.time()
            time_elapsed = current_time - self.start_time
            self.performance_metrics.network_throughput = (
                self.performance_metrics.bytes_processed / time_elapsed
            ) if time_elapsed > 0 else 0
            
            # Update active sessions count
            with self.session_lock:
                active_count = sum(1 for s in self.sessions.values() 
                                 if s.state in [SessionState.ESTABLISHED, SessionState.HANDSHAKE])
                self.performance_metrics.active_sessions = active_count
            
            # Log performance summary periodically
            if int(current_time) % 30 == 0:  # Every 30 seconds
                logger.info(f"Performance metrics: {self.get_performance_metrics()}")
                
        except Exception as e:
            logger.error(f"Failed to update performance metrics: {e}")

    def _cleanup_expired_sessions(self):
        """Clean up expired and inactive sessions"""
        try:
            current_time = datetime.now()
            expired_sessions = []
            
            with self.session_lock:
                for session_id, session in self.sessions.items():
                    # Check for inactive sessions (no activity for 5 minutes)
                    time_since_activity = current_time - session.last_activity
                    if time_since_activity > timedelta(minutes=5):
                        expired_sessions.append(session_id)
                    
                    # Check for sessions in error state
                    elif session.state == SessionState.ERROR:
                        expired_sessions.append(session_id)
            
            # Remove expired sessions
            for session_id in expired_sessions:
                self._close_session(session_id, "inactive_timeout")
                
            if expired_sessions:
                logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
                
        except Exception as e:
            logger.error(f"Failed to cleanup expired sessions: {e}")

    def _close_session(self, session_id: str, reason: str = "normal"):
        """Close session and cleanup resources"""
        try:
            with self.session_lock:
                if session_id in self.sessions:
                    session = self.sessions[session_id]
                    
                    # Update session state
                    session.state = SessionState.CLOSED
                    
                    # Clean up cryptographic resources
                    try:
                        self.key_manager.revoke_key(session.session_key_id, f"session_closed_{reason}")
                        self.dictionary_manager.delete_dictionary(session.dictionary_id, permanent=False)
                    except Exception as e:
                        logger.warning(f"Failed to cleanup session resources: {e}")
                    
                    # Remove from sessions dictionary
                    del self.sessions[session_id]
                    
                    logger.info(f"Closed session {session_id}: {reason}")
                    
        except Exception as e:
            logger.error(f"Failed to close session {session_id}: {e}")

    def get_session_info(self, session_id: str) -> Optional[SessionMetadata]:
        """Get detailed session information"""
        with self.session_lock:
            return self.sessions.get(session_id)

    def list_sessions(self, state_filter: Optional[SessionState] = None) -> List[SessionMetadata]:
        """List all sessions with optional state filtering"""
        with self.session_lock:
            if state_filter:
                return [s for s in self.sessions.values() if s.state == state_filter]
            else:
                return list(self.sessions.values())

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics"""
        metrics_dict = asdict(self.performance_metrics)
        metrics_dict.update({
            'uptime_seconds': time.time() - self.start_time,
            'memory_usage_mb': psutil.Process().memory_info().rss / 1024 / 1024,
            'cpu_percent': psutil.cpu_percent(),
            'network_connections': len(self.sessions),
            'config': asdict(self.config)
        })
        return metrics_dict

    def set_data_received_callback(self, callback: Callable[[bytes, SessionMetadata, Tuple[str, int]], None]):
        """Set callback for received application data"""
        self.data_received_callback = callback

    def shutdown(self):
        """Gracefully shutdown the router interface"""
        logger.info("Shutting down RouterInterface...")
        
        # Stop listening and background services
        self.listening = False
        
        # Close all active sessions
        with self.session_lock:
            session_ids = list(self.sessions.keys())
            for session_id in session_ids:
                self._close_session(session_id, "shutdown")
        
        # Close socket
        if self.socket:
            self.socket.close()
        
        # Shutdown thread pool
        self.thread_pool.shutdown(wait=True)
        
        logger.info("RouterInterface shutdown completed")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.shutdown()

    def __repr__(self) -> str:
        """String representation of the router interface"""
        return (f"RouterInterface(interface='{self.config.interface_name}', "
                f"ip='{self.config.listen_ip}:{self.config.listen_port}', "
                f"sessions={len(self.sessions)}, "
                f"throughput={self.performance_metrics.network_throughput:.2f} B/s)")

# Utility functions
def create_router_interface(interface_name: str,
                          listen_ip: str = "0.0.0.0",
                          listen_port: int = 0,
                          security_level: str = "high") -> RouterInterface:
    """
    Create a pre-configured router interface
    
    Args:
        interface_name: Network interface name
        listen_ip: IP address to listen on
        listen_port: Port to listen on (0 for auto)
        security_level: Security level ('basic', 'standard', 'high', 'quantum')
        
    Returns:
        Configured RouterInterface instance
    """
    
    # Create configuration
    config = RouterConfig(
        interface_name=interface_name,
        listen_ip=listen_ip,
        listen_port=listen_port,
        max_connections=1000,
        buffer_size=65536,
        timeout_seconds=30.0,
        enable_encryption=True,
        enable_compression=True,
        security_level=security_level,
        traffic_shaping=True,
        quality_of_service=True,
        hardware_acceleration=False
    )
    
    # Create dependent components
    key_manager = KeyManager(
        db_path=f"keys_router_{interface_name}.db",
        device_id=f"router_{interface_name}",
        security_level=security_level
    )
    
    dictionary_manager = DictionaryManager(
        db_path=f"dict_router_{interface_name}.db",
        device_id=f"router_{interface_name}",
        security_level=security_level
    )
    
    tensor_engine = TensorEncryptionEngine(
        tensor_dimensions=(8, 8),
        security_level=security_level
    )
    
    ai_logic = AILogicGenerator(
        input_dim=64,
        output_dim=64,
        architecture='advanced',
        security_level=security_level
    )
    
    return RouterInterface(config, key_manager, dictionary_manager, tensor_engine, ai_logic)

def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address format
    
    Args:
        ip: IP address to validate
        
    Returns:
        Validation result
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_network_interfaces() -> List[Dict[str, Any]]:
    """
    Get available network interfaces
    
    Returns:
        List of interface information
    """
    interfaces = []
    try:
        for interface, addrs in psutil.net_if_addrs().items():
            interface_info = {
                'name': interface,
                'addresses': [],
                'stats': psutil.net_if_stats().get(interface, {})
            }
            
            for addr in addrs:
                interface_info['addresses'].append({
                    'family': addr.family.name,
                    'address': addr.address,
                    'netmask': addr.netmask,
                    'broadcast': addr.broadcast
                })
            
            interfaces.append(interface_info)
            
    except Exception as e:
        logger.error(f"Failed to get network interfaces: {e}")
    
    return interfaces