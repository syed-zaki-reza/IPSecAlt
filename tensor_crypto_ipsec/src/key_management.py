"""
Key Manager - Hierarchical Key Lifecycle Management

Manages cryptographic key derivation, rotation, and secure storage.
Implements forward secrecy through automatic key rotation.

Features:
- HKDF-based hierarchical key derivation
- Session-specific tensor/AI/dictionary keys
- Automatic time-based and usage-based rotation
- AES-encrypted SQLite storage
- LRU memory caching with TTL
"""

import hashlib
import time
import sqlite3
import threading
from typing import Dict, Optional, Any, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class KeyState(Enum):
    """Key lifecycle states"""
    ACTIVE = "active"
    ROTATING = "rotating"
    DEPRECATED = "deprecated"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class KeyInfo:
    """Key metadata and state"""
    key_id: str
    parent_key_id: Optional[str]
    context: str
    state: KeyState
    created_at: float
    expires_at: float
    usage_count: int = 0
    max_usage: int = 10000
    key_bytes: Optional[bytes] = None
    
    def is_expired(self) -> bool:
        return time.time() > self.expires_at
    
    def needs_rotation(self) -> bool:
        return (self.usage_count >= self.max_usage or 
                self.is_expired() or
                time.time() > self.expires_at - 300)  # 5 min grace


class KeyManager:
    """
    Hierarchical Key Manager with Forward Secrecy.
    
    Manages key derivation using HKDF, automatic rotation,
    and secure encrypted storage.
    
    Attributes:
        master_key: Root master key for derivation
        db_path: SQLite database path for key storage
        cache: In-memory LRU cache for active keys
    """
    
    DEFAULT_KEY_LENGTH = 32  # 256 bits
    DEFAULT_TTL = 3600  # 1 hour
    SALT = b'tensor_crypto_derivation_salt_v1'
    
    def __init__(
        self,
        master_key: Optional[bytes] = None,
        db_path: str = ":memory:",
        cache_size: int = 100
    ):
        """
        Initialize Key Manager.
        
        Args:
            master_key: Master key (generated if None)
            db_path: SQLite database path
            cache_size: Maximum cached keys
        """
        self.master_key = master_key or os.urandom(32)
        self.db_path = db_path
        self.cache_size = cache_size
        self.cache: Dict[str, KeyInfo] = {}
        self._lock = threading.RLock()
        
        # Initialize database
        self._init_db()
    
    def _init_db(self):
        """Initialize SQLite database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                key_id TEXT PRIMARY KEY,
                parent_key_id TEXT,
                context TEXT,
                state TEXT,
                created_at REAL,
                expires_at REAL,
                usage_count INTEGER,
                max_usage INTEGER,
                encrypted_key BLOB,
                iv BLOB,
                created_by TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_context ON keys(context)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_state ON keys(state)
        ''')
        
        conn.commit()
        conn.close()
    
    def _derive_key(
        self,
        parent_key: bytes,
        context: str,
        key_id: str,
        length: int = DEFAULT_KEY_LENGTH
    ) -> bytes:
        """
        Derive child key using HKDF.
        
        Args:
            parent_key: Parent key for derivation
            context: Key context/purpose
            key_id: Unique key identifier
            length: Desired key length
            
        Returns:
            Derived key bytes
        """
        info = f"{context}:{key_id}".encode()
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=self.SALT,
            info=info,
            backend=default_backend()
        )
        
        return hkdf.derive(parent_key)
    
    def _encrypt_key(self, key: bytes) -> Tuple[bytes, bytes]:
        """Encrypt key with master key using AES-CTR"""
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.CTR(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(key) + encryptor.finalize()
        return encrypted, iv
    
    def _decrypt_key(self, encrypted: bytes, iv: bytes) -> bytes:
        """Decrypt key with master key"""
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.CTR(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted) + decryptor.finalize()
    
    def create_key(
        self,
        context: str,
        parent_key_id: Optional[str] = None,
        ttl: float = DEFAULT_TTL,
        max_usage: int = 10000
    ) -> KeyInfo:
        """
        Create new key with hierarchical derivation.
        
        Args:
            context: Key purpose/context
            parent_key_id: Parent key ID (uses master if None)
            ttl: Time-to-live in seconds
            max_usage: Maximum usage count before rotation
            
        Returns:
            KeyInfo with derived key
        """
        with self._lock:
            current_time = time.time()
            key_id = hashlib.sha256(
                f"{context}:{current_time}:{os.urandom(8).hex()}".encode()
            ).hexdigest()[:16]
            
            # Get parent key
            if parent_key_id and parent_key_id != "master":
                parent_info = self.get_key(parent_key_id)
                if not parent_info or not parent_info.key_bytes:
                    raise ValueError(f"Parent key {parent_key_id} not found")
                parent_key = parent_info.key_bytes
            else:
                parent_key = self.master_key
            
            # Derive new key
            key_bytes = self._derive_key(parent_key, context, key_id)
            
            # Encrypt for storage
            encrypted, iv = self._encrypt_key(key_bytes)
            
            # Create key info
            key_info = KeyInfo(
                key_id=key_id,
                parent_key_id=parent_key_id,
                context=context,
                state=KeyState.ACTIVE,
                created_at=current_time,
                expires_at=current_time + ttl,
                usage_count=0,
                max_usage=max_usage,
                key_bytes=key_bytes
            )
            
            # Store in database
            self._store_key(key_info, encrypted, iv)
            
            # Cache
            self._cache_key(key_info)
            
            logger.debug(f"Created key {key_id} for context {context}")
            return key_info
    
    def _store_key(self, key_info: KeyInfo, encrypted: bytes, iv: bytes):
        """Store key in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO keys 
            (key_id, parent_key_id, context, state, created_at, expires_at,
             usage_count, max_usage, encrypted_key, iv, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            key_info.key_id,
            key_info.parent_key_id,
            key_info.context,
            key_info.state.value,
            key_info.created_at,
            key_info.expires_at,
            key_info.usage_count,
            key_info.max_usage,
            encrypted,
            iv,
            "system"
        ))
        
        conn.commit()
        conn.close()
    
    def _cache_key(self, key_info: KeyInfo):
        """Add key to LRU cache"""
        with self._lock:
            if len(self.cache) >= self.cache_size:
                # Remove oldest expired/deprecated key
                for kid, info in list(self.cache.items()):
                    if info.is_expired() or info.state == KeyState.DEPRECATED:
                        del self.cache[kid]
                        break
            
            self.cache[key_info.key_id] = key_info
    
    def get_key(self, key_id: str) -> Optional[KeyInfo]:
        """
        Retrieve key by ID.
        
        Args:
            key_id: Key identifier
            
        Returns:
            KeyInfo with decrypted key bytes, or None if not found
        """
        # Check cache first
        if key_id in self.cache:
            key_info = self.cache[key_id]
            if not key_info.is_expired() and key_info.state == KeyState.ACTIVE:
                key_info.usage_count += 1
                return key_info
        
        # Query database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT key_id, parent_key_id, context, state, created_at, expires_at,
                   usage_count, max_usage, encrypted_key, iv
            FROM keys WHERE key_id = ?
        ''', (key_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        key_info = KeyInfo(
            key_id=row[0],
            parent_key_id=row[1],
            context=row[2],
            state=KeyState(row[3]),
            created_at=row[4],
            expires_at=row[5],
            usage_count=row[6],
            max_usage=row[7]
        )
        
        # Decrypt key
        if row[8] and row[9]:
            key_info.key_bytes = self._decrypt_key(row[8], row[9])
        
        # Cache and increment usage
        key_info.usage_count += 1
        self._cache_key(key_info)
        
        return key_info
    
    def rotate_key(self, key_id: str) -> Optional[KeyInfo]:
        """
        Rotate key (deprecate old, create new).
        
        Args:
            key_id: Key to rotate
            
        Returns:
            New KeyInfo, or None if original not found
        """
        with self._lock:
            old_key = self.get_key(key_id)
            if not old_key:
                return None
            
            logger.info(f"Rotating key {key_id}")
            
            # Mark old key as deprecated
            old_key.state = KeyState.DEPRECATED
            self._update_key_state(old_key)
            
            # Create new key with same context
            new_key = self.create_key(
                context=old_key.context,
                parent_key_id=old_key.parent_key_id,
                ttl=old_key.expires_at - old_key.created_at,
                max_usage=old_key.max_usage
            )
            
            return new_key
    
    def _update_key_state(self, key_info: KeyInfo):
        """Update key state in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE keys SET state = ?, usage_count = ?
            WHERE key_id = ?
        ''', (key_info.state.value, key_info.usage_count, key_info.key_id))
        
        conn.commit()
        conn.close()
    
    def delete_key(self, key_id: str) -> bool:
        """Delete key from storage"""
        with self._lock:
            if key_id in self.cache:
                del self.cache[key_id]
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM keys WHERE key_id = ?', (key_id,))
            deleted = cursor.rowcount > 0
            conn.commit()
            conn.close()
            
            return deleted
    
    def get_session_keys(
        self,
        session_id: str,
        device_fingerprint: str
    ) -> Dict[str, KeyInfo]:
        """
        Generate/retrieve all keys needed for a session.
        
        Args:
            session_id: Session identifier
            device_fingerprint: Device fingerprint
            
        Returns:
            Dictionary with 'tensor', 'ai', 'dictionary' keys
        """
        base_context = f"session:{session_id}:{device_fingerprint}"
        
        keys = {}
        
        # Tensor encryption key
        keys['tensor'] = self.create_key(
            context=f"{base_context}:tensor",
            ttl=900  # 15 minutes
        )
        
        # AI logic key
        keys['ai'] = self.create_key(
            context=f"{base_context}:ai",
            ttl=900
        )
        
        # Dictionary sync key
        keys['dictionary'] = self.create_key(
            context=f"{base_context}:dictionary",
            ttl=1800  # 30 minutes
        )
        
        return keys
    
    def cleanup_expired(self) -> int:
        """Remove expired keys from database"""
        with self._lock:
            current_time = time.time()
            
            # Clean cache
            expired_cache = [
                kid for kid, info in self.cache.items()
                if info.is_expired()
            ]
            for kid in expired_cache:
                del self.cache[kid]
            
            # Clean database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                DELETE FROM keys WHERE expires_at < ? AND state IN (?, ?)
            ''', (current_time, KeyState.EXPIRED.value, KeyState.DEPRECATED.value))
            
            deleted = cursor.rowcount
            conn.commit()
            conn.close()
            
            return deleted + len(expired_cache)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get key manager statistics"""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT state, COUNT(*) FROM keys GROUP BY state')
            state_counts = dict(cursor.fetchall())
            
            cursor.execute('SELECT COUNT(*) FROM keys')
            total = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_keys': total,
                'keys_by_state': state_counts,
                'cached_keys': len(self.cache),
                'cache_size_limit': self.cache_size
            }
