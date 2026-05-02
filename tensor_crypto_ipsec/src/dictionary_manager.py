"""
Dictionary Manager - Secure Shared Dictionary Generation & Synchronization

Manages manufacturer-embedded dictionary systems for hardware-rooted key
provisioning and forward secrecy.

Features:
- Deterministic dictionary generation from manufacturer keys
- Peer synchronization with HMAC authentication
- Auto-refresh with usage/time-based triggers
- Compression + encryption for transmission
"""

import hashlib
import time
import secrets
from typing import Dict, Optional, Any, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
import json
import zlib

logger = logging.getLogger(__name__)


@dataclass
class DictionaryEntry:
    """Single dictionary entry"""
    key: int  # uint24 (3 bytes)
    value: bytes
    created_at: float
    access_count: int = 0


@dataclass
class DictionaryInfo:
    """Dictionary metadata"""
    dict_id: str
    version: int
    size: int
    created_at: float
    expires_at: float
    entries: Dict[int, DictionaryEntry] = field(default_factory=dict)
    sync_peers: List[str] = field(default_factory=list)
    
    def is_expired(self) -> bool:
        return time.time() > self.expires_at
    
    def needs_refresh(self) -> bool:
        # Refresh at 80% of lifetime
        return time.time() > (self.created_at + (self.expires_at - self.created_at) * 0.8)


class DictionaryManager:
    """
    Shared Dictionary Manager for Hardware-Rooted Provisioning.
    
    Simulates manufacturer-embedded dictionaries using deterministic
    generation from device fingerprints and session parameters.
    
    Attributes:
        manufacturer_key: Simulated manufacturer provisioning key
        dictionaries: Active dictionary registry
        refresh_interval: Default dictionary lifetime
    """
    
    DEFAULT_DICT_SIZE = 1024  # Number of entries
    DEFAULT_ENTRY_SIZE = 64  # Max bytes per entry
    REFRESH_INTERVAL = 3600  # 1 hour default
    
    def __init__(
        self,
        manufacturer_key: Optional[bytes] = None,
        refresh_interval: float = REFRESH_INTERVAL
    ):
        """
        Initialize Dictionary Manager.
        
        Args:
            manufacturer_key: Simulated manufacturer key (generated if None)
            refresh_interval: Default dictionary refresh interval
        """
        self.manufacturer_key = manufacturer_key or secrets.token_bytes(32)
        self.refresh_interval = refresh_interval
        self.dictionaries: Dict[str, DictionaryInfo] = {}
        self._lock = __import__('threading').RLock()
    
    def generate_dictionary(
        self,
        device_pair: str,
        session_id: str,
        dict_type: str = "primary",
        size: int = DEFAULT_DICT_SIZE
    ) -> DictionaryInfo:
        """
        Generate deterministic shared dictionary.
        
        Args:
            device_pair: Combined device fingerprints
            session_id: Session identifier
            dict_type: Dictionary type/purpose
            size: Number of entries
            
        Returns:
            DictionaryInfo with generated entries
        """
        current_time = time.time()
        dict_id = hashlib.sha256(
            f"{device_pair}:{session_id}:{dict_type}".encode()
        ).hexdigest()[:16]
        
        # Generate deterministic seed
        seed = hashlib.pbkdf2_hmac(
            'sha256',
            self.manufacturer_key,
            f"{device_pair}:{session_id}:{dict_type}".encode(),
            iterations=10000
        )
        
        # Create dictionary info
        dict_info = DictionaryInfo(
            dict_id=dict_id,
            version=1,
            size=size,
            created_at=current_time,
            expires_at=current_time + self.refresh_interval
        )
        
        # Generate entries deterministically
        import numpy as np
        np.random.seed(int.from_bytes(seed[:8], byteorder='big'))
        
        for i in range(size):
            # Generate 24-bit key
            entry_key = np.random.randint(0, 2**24)
            
            # Generate random value
            value_size = np.random.randint(16, self.DEFAULT_ENTRY_SIZE)
            value = np.random.bytes(value_size)
            
            dict_info.entries[entry_key] = DictionaryEntry(
                key=int(entry_key),
                value=value,
                created_at=current_time
            )
        
        # Reset random state
        np.random.seed(None)
        
        with self._lock:
            self.dictionaries[dict_id] = dict_info
        
        logger.debug(f"Generated dictionary {dict_id} with {size} entries")
        return dict_info
    
    def get_dictionary(self, dict_id: str) -> Optional[DictionaryInfo]:
        """Retrieve dictionary by ID"""
        with self._lock:
            dict_info = self.dictionaries.get(dict_id)
            
            if dict_info and not dict_info.is_expired():
                return dict_info
            
            return None
    
    def lookup_entry(
        self,
        dict_id: str,
        entry_key: int
    ) -> Optional[bytes]:
        """
        Lookup entry in dictionary.
        
        Args:
            dict_id: Dictionary identifier
            entry_key: 24-bit entry key
            
        Returns:
            Entry value or None
        """
        dict_info = self.get_dictionary(dict_id)
        if not dict_info:
            return None
        
        entry = dict_info.entries.get(entry_key)
        if entry:
            entry.access_count += 1
            return entry.value
        
        return None
    
    def synchronize_with_peer(
        self,
        local_dict: DictionaryInfo,
        peer_fingerprint: str,
        hmac_key: bytes
    ) -> Tuple[bool, str]:
        """
        Synchronize dictionary with peer device.
        
        Args:
            local_dict: Local dictionary to sync
            peer_fingerprint: Peer device fingerprint
            hmac_key: Key for HMAC authentication
            
        Returns:
            Tuple of (success, message)
        """
        # Generate sync payload
        payload = {
            'dict_id': local_dict.dict_id,
            'version': local_dict.version,
            'timestamp': time.time(),
            'entry_count': len(local_dict.entries)
        }
        
        # Create HMAC
        payload_bytes = json.dumps(payload, sort_keys=True).encode()
        hmac = hashlib.hmac_new(hmac_key, payload_bytes, digestmod=hashlib.sha256)
        
        # In production, send payload + hmac to peer
        # For prototype, simulate successful sync
        logger.debug(f"Syncing dictionary {local_dict.dict_id} with peer {peer_fingerprint[:8]}...")
        
        with self._lock:
            if local_dict.dict_id not in local_dict.sync_peers:
                local_dict.sync_peers.append(peer_fingerprint)
        
        return True, "Synchronization successful"
    
    def refresh_dictionary(
        self,
        dict_id: str,
        device_pair: str,
        session_id: str,
        dict_type: str = "primary"
    ) -> Optional[DictionaryInfo]:
        """
        Refresh dictionary with new entries.
        
        Args:
            dict_id: Current dictionary ID
            device_pair: Device fingerprints
            session_id: Session identifier
            dict_type: Dictionary type
            
        Returns:
            New DictionaryInfo, or None if original not found
        """
        old_dict = self.get_dictionary(dict_id)
        if not old_dict:
            return None
        
        logger.info(f"Refreshing dictionary {dict_id}")
        
        # Mark old as expired
        old_dict.expires_at = time.time()
        
        # Generate new dictionary with incremented version
        new_dict = self.generate_dictionary(
            device_pair=device_pair,
            session_id=f"{session_id}:v{old_dict.version + 1}",
            dict_type=dict_type,
            size=old_dict.size
        )
        
        new_dict.version = old_dict.version + 1
        
        return new_dict
    
    def export_for_transmission(
        self,
        dict_id: str,
        encryption_key: bytes
    ) -> Optional[bytes]:
        """
        Export dictionary for secure transmission.
        
        Compresses and encrypts dictionary entries.
        
        Args:
            dict_id: Dictionary to export
            encryption_key: AES encryption key
            
        Returns:
            Encrypted compressed bytes, or None if not found
        """
        dict_info = self.get_dictionary(dict_id)
        if not dict_info:
            return None
        
        # Serialize entries
        entries_data = []
        for entry in dict_info.entries.values():
            entries_data.append({
                'key': entry.key,
                'value': entry.value.hex(),
                'created_at': entry.created_at
            })
        
        serialized = json.dumps(entries_data).encode()
        
        # Compress
        compressed = zlib.compress(serialized, level=6)
        
        # Encrypt (simplified - use XOR for prototype)
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        iv = secrets.token_bytes(16)
        cipher = Cipher(
            algorithms.AES(encryption_key[:32].ljust(32, b'\0')),
            modes.CTR(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(compressed) + encryptor.finalize()
        
        # Prepend IV
        return iv + encrypted
    
    def import_from_transmission(
        self,
        encrypted_data: bytes,
        decryption_key: bytes
    ) -> Optional[DictionaryInfo]:
        """
        Import dictionary from received transmission.
        
        Args:
            encrypted_data: Encrypted compressed data (IV + ciphertext)
            decryption_key: AES decryption key
            
        Returns:
            Imported DictionaryInfo, or None on failure
        """
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            # Extract IV and ciphertext
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            # Decrypt
            cipher = Cipher(
                algorithms.AES(decryption_key[:32].ljust(32, b'\0')),
                modes.CTR(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            compressed = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Decompress
            serialized = zlib.decompress(compressed)
            
            # Parse entries
            entries_data = json.loads(serialized)
            
            # Create dictionary info
            current_time = time.time()
            dict_info = DictionaryInfo(
                dict_id=hashlib.sha256(serialized).hexdigest()[:16],
                version=1,
                size=len(entries_data),
                created_at=current_time,
                expires_at=current_time + self.refresh_interval
            )
            
            for item in entries_data:
                dict_info.entries[item['key']] = DictionaryEntry(
                    key=item['key'],
                    value=bytes.fromhex(item['value']),
                    created_at=item['created_at']
                )
            
            with self._lock:
                self.dictionaries[dict_info.dict_id] = dict_info
            
            logger.debug(f"Imported dictionary with {len(entries_data)} entries")
            return dict_info
            
        except Exception as e:
            logger.error(f"Failed to import dictionary: {e}")
            return None
    
    def cleanup_expired(self) -> int:
        """Remove expired dictionaries"""
        with self._lock:
            expired_ids = [
                did for did, dinfo in self.dictionaries.items()
                if dinfo.is_expired()
            ]
            
            for did in expired_ids:
                del self.dictionaries[did]
            
            if expired_ids:
                logger.debug(f"Cleaned up {len(expired_ids)} expired dictionaries")
            
            return len(expired_ids)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get dictionary manager statistics"""
        with self._lock:
            total_entries = sum(len(d.entries) for d in self.dictionaries.values())
            
            return {
                'active_dictionaries': len(self.dictionaries),
                'total_entries': total_entries,
                'default_size': self.DEFAULT_DICT_SIZE,
                'refresh_interval': self.refresh_interval,
                'expired_count': sum(1 for d in self.dictionaries.values() if d.is_expired())
            }
