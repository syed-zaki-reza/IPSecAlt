import sys
import os
import enum
import time

# Adjust path to allow imports from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from identity.hardware_fingerprint import HardwareFingerprint
from identity.key_manager import KeyManager
from core.encryption_service import EncryptionService
from network.protocol import ProtocolHandler, Packet, PacketType

class ConnectionState(enum.Enum):
    DISCONNECTED = 0
    HANDSHAKE_INIT = 1  # Sent Hello/PubKey
    SECURE = 2          # Shared Secret Established

class RouterNode:
    """
    Represents a Network Device running the LCTC Hybrid Protocol.
    """

    def __init__(self, node_name: str):
        self.node_name = node_name
        
        # 1. Identity & Keys (Asymmetric Layer)
        self.hw = HardwareFingerprint()
        self.key_mgr = KeyManager(self.hw.get_device_id())
        
        # 2. Network Utilities
        self.protocol = ProtocolHandler()
        self.state = ConnectionState.DISCONNECTED
        
        # 3. Session Data
        self.peer_id = None
        self.shared_secret = None
        self.crypto_service = None # Will be initialized after handshake

        print(f"[{self.node_name}] Online. ID: {self.hw.get_device_id()}")

    def initiate_handshake(self) -> bytes:
        """
        Starts the connection by creating a PUBKEY_OFFER packet.
        Returns: Raw bytes to send to peer.
        """
        self.state = ConnectionState.HANDSHAKE_INIT
        
        # Create Packet containing our Chebyshev Public Key
        pub_key = self.key_mgr.get_public_key()
        packet = Packet(PacketType.PUBKEY_OFFER, self.hw.get_device_id(), pub_key)
        
        print(f"[{self.node_name}] Initiating Handshake. Sending PubKey: {pub_key:.6f}...")
        return self.protocol.serialize(packet)

    def process_incoming_packet(self, raw_bytes: bytes) -> bytes:
        """
        Main Event Loop. 
        Input: Raw network bytes.
        Output: Response bytes (if any), or None.
        """
        packet = self.protocol.deserialize(raw_bytes)
        if not packet:
            print(f"[{self.node_name}] Error: Malformed Packet.")
            return None

        # Logic based on Packet Type
        if packet.ptype == PacketType.PUBKEY_OFFER:
            return self._handle_pubkey(packet)
            
        elif packet.ptype == PacketType.DATA:
            return self._handle_data(packet)
            
        return None

    def _handle_pubkey(self, packet: Packet) -> bytes:
        """
        Received a Peer's Public Key. 
        Action: Derive Secret -> Upgrade to SECURE -> (Optional) Reply with my Key.
        """
        print(f"[{self.node_name}] Received PubKey from {packet.sender_id}")
        self.peer_id = packet.sender_id
        
        # 1. Math: Derive the Shared Secret
        self.shared_secret = self.key_mgr.compute_shared_secret(packet.payload)
        print(f"[{self.node_name}] Derived Shared Secret: {self.shared_secret:.10f}")
        
        # 2. Setup: Initialize Symmetric Engine
        self.crypto_service = EncryptionService(self.shared_secret)
        self.state = ConnectionState.SECURE
        
        # 3. Response Logic
        # If I initiated, I'm done. If I didn't, I must send MY key back.
        # Simple heuristic: If I haven't sent a key yet, reply.
        # (In a real protocol, we'd track 'Initiator' vs 'Responder')
        # For simulation, we assume if we are just now seeing a key, we might need to reply.
        return None 

    def reply_handshake(self) -> bytes:
        """
        Explicitly generates a Public Key reply (for the Responder).
        """
        pub_key = self.key_mgr.get_public_key()
        packet = Packet(PacketType.PUBKEY_OFFER, self.hw.get_device_id(), pub_key)
        print(f"[{self.node_name}] Replying with My PubKey...")
        return self.protocol.serialize(packet)

    def send_data(self, message: str) -> bytes:
        """
        Encrypts and sends a message (only if SECURE).
        """
        if self.state != ConnectionState.SECURE:
            raise RuntimeError("Cannot send data: Handshake not complete.")
            
        # Encrypt using Symmetric Engine
        ciphertext = self.crypto_service.encrypt_message(message)
        
        # Wrap in Packet
        packet = Packet(PacketType.DATA, self.hw.get_device_id(), ciphertext)
        return self.protocol.serialize(packet)

    def _handle_data(self, packet: Packet):
        """
        Decrypts incoming data.
        """
        if self.state != ConnectionState.SECURE:
            print(f"[{self.node_name}] Dropped Data: No Session.")
            return None
            
        plaintext = self.crypto_service.decrypt_message(packet.payload)
        print(f"[{self.node_name}] Decrypted Message from {packet.sender_id}: '{plaintext}'")
        return plaintext

# --- Unit Test ---
if __name__ == "__main__":
    print("[TEST] Router Logic...")
    # This logic is complex to unit test in isolation because it requires two interacting objects.
    # We will defer the full test to 'main_simulation.py'.
    r = RouterNode("TEST_NODE")
    print(f"Node initialized in state: {r.state}")