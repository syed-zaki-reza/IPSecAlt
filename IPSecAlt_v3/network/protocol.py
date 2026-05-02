import json
import struct
import enum
from dataclasses import dataclass
from typing import Any, Optional

class PacketType(enum.Enum):
    HELLO = 1          # "I am Router A"
    PUBKEY_OFFER = 2   # "Here is my Chebyshev Public Key"
    DATA = 3           # "Here is Encrypted Video/File"

@dataclass
class Packet:
    """
    Represents a unified network packet for the LCTC protocol.
    """
    ptype: PacketType
    sender_id: str
    payload: Any # Can be float (PubKey) or bytes (Encrypted Data)

class ProtocolHandler:
    """
    Handles serialization/deserialization of network packets.
    
    Format:
    [ Type (1B) | ID_Len (1B) | Sender_ID (N) | Payload_Len (4B) | Payload (M) ]
    """

    def __init__(self):
        # Struct format: 
        # B = unsigned char (1 byte)
        # I = unsigned int (4 bytes)
        self.header_struct = ">B B" 
        self.len_struct = ">I"

    def serialize(self, packet: Packet) -> bytes:
        """Converts a Packet object into wire-ready bytes."""
        
        # 1. Encode Sender ID
        id_bytes = packet.sender_id.encode('utf-8')
        id_len = len(id_bytes)
        if id_len > 255:
            raise ValueError("Sender ID too long for prototype protocol")

        # 2. Encode Payload
        if packet.ptype == PacketType.PUBKEY_OFFER:
            # Payload is a float (Public Key)
            # We wrap it in JSON for safe float transmission
            payload_bytes = json.dumps({"k": packet.payload}).encode('utf-8')
        elif packet.ptype == PacketType.DATA:
            # Payload is already bytes (Ciphertext)
            payload_bytes = packet.payload
        elif packet.ptype == PacketType.HELLO:
            payload_bytes = b"HELLO_ACK"
        else:
            raise ValueError("Unknown Packet Type")

        payload_len = len(payload_bytes)

        # 3. Pack Header: [Type] [ID_Len]
        header = struct.pack(self.header_struct, packet.ptype.value, id_len)
        
        # 4. Pack Length: [Payload_Len]
        length_field = struct.pack(self.len_struct, payload_len)
        
        # 5. Concatenate All
        return header + id_bytes + length_field + payload_bytes

    def deserialize(self, raw_bytes: bytes) -> Packet:
        """Parses wire bytes back into a Packet object."""
        try:
            offset = 0
            
            # 1. Read Header (Type + ID Len)
            type_val, id_len = struct.unpack_from(self.header_struct, raw_bytes, offset)
            offset += struct.calcsize(self.header_struct)
            
            # 2. Read Sender ID
            id_bytes = raw_bytes[offset : offset + id_len]
            sender_id = id_bytes.decode('utf-8')
            offset += id_len
            
            # 3. Read Payload Length
            payload_len = struct.unpack_from(self.len_struct, raw_bytes, offset)[0]
            offset += struct.calcsize(self.len_struct)
            
            # 4. Read Payload
            payload_raw = raw_bytes[offset : offset + payload_len]
            
            # 5. Reconstruct Object
            ptype = PacketType(type_val)
            
            if ptype == PacketType.PUBKEY_OFFER:
                # Extract float from JSON wrapper
                data = json.loads(payload_raw.decode('utf-8'))
                payload = float(data["k"])
            elif ptype == PacketType.DATA:
                payload = payload_raw # Keep as bytes
            else:
                payload = None
                
            return Packet(ptype, sender_id, payload)
            
        except Exception as e:
            print(f"[Protocol] Error parsing packet: {e}")
            return None

# --- Unit Test ---
if __name__ == "__main__":
    print("[TEST] Testing Protocol Handler...")
    
    handler = ProtocolHandler()
    
    # Test 1: Handshake Packet (Float Payload)
    pk_packet = Packet(PacketType.PUBKEY_OFFER, "ROUTER_A", 0.123456789)
    wire_bytes = handler.serialize(pk_packet)
    print(f"[TX] PubKey Packet Size: {len(wire_bytes)} bytes")
    
    decoded_pk = handler.deserialize(wire_bytes)
    print(f"[RX] Type: {decoded_pk.ptype}, Key: {decoded_pk.payload}")
    assert decoded_pk.payload == 0.123456789
    
    # Test 2: Data Packet (Bytes Payload)
    enc_data = b"\xDE\xAD\xBE\xEF" * 4
    data_packet = Packet(PacketType.DATA, "ROUTER_A", enc_data)
    wire_bytes_2 = handler.serialize(data_packet)
    print(f"[TX] Data Packet Size: {len(wire_bytes_2)} bytes")
    
    decoded_data = handler.deserialize(wire_bytes_2)
    print(f"[RX] Type: {decoded_data.ptype}, Data Matches: {decoded_data.payload == enc_data}")
    assert decoded_data.payload == enc_data
    
    print("[SUCCESS] Protocol serialization working correctly.")