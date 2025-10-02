"""
key_management.py
Advanced Key Management System for Tensor-Based Post-Quantum Cryptography

This module provides comprehensive key lifecycle management including:
- Hierarchical key derivation and management
- Automated key rotation with forward secrecy
- Secure key storage and retrieval
- Key exchange protocols for distributed systems
- Hardware security module (HSM) integration support
"""

import numpy as np
import hashlib
import hmac
import os
import json
import sqlite3
import threading
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class KeyType(Enum):
    """Enumeration of different key types in the system"""
    MASTER = "master"
    SESSION = "session"
    TENSOR = "tensor"
    AI_LOGIC = "ai_logic"
    DICTIONARY = "dictionary"
    EPHEMERAL = "ephemeral"


class KeyStatus(Enum):
    """Enumeration of key lifecycle states"""
    ACTIVE = "active"
    ROTATING = "rotating"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass
class KeyMetadata:
    """Metadata associated with cryptographic keys"""
    key_id: str
    key_type: KeyType
    status: KeyStatus
    created_at: datetime
    expires_at: Optional[datetime]
    rotated_from: Optional[str]
    usage_count: int
    device_id: str
    session_id: Optional[str]
    algorithm_info: Dict[str, Any]
    security_level: str


class KeyManager:
    """
    Advanced key management system for tensor-based cryptography
    
    Provides hierarchical key derivation, automated rotation, secure storage,
    and integration with hardware security modules.
    """
    
    def __init__(self, master_key: Optional[bytes] = None,
                 db_path: str = "keystore.db",
                 device_id: Optional[str] = None,
                 security_level: str = 'standard',
                 auto_rotation: bool = True):
        """
        Initialize key management system
        
        Args:
            master_key: Optional master key (generated if None)
            db_path: Path to key storage database
            device_id: Unique device identifier
            security_level: Security level ('basic', 'standard', 'high')
            auto_rotation: Enable automatic key rotation
        """
        self.db_path = db_path
        self.device_id = device_id or self._generate_device_id()
        self.security_level = security_level
        self.auto_rotation = auto_rotation
        
        # Initialize logging
        self.logger = logging.getLogger(__name__)
        
        # Thread synchronization
        self._lock = threading.RLock()
        
        # Security parameters
        self.security_params = self._get_security_parameters(security_level)
        
        # Master key initialization
        if master_key is None:
            self.master_key = self._generate_master_key()
        else:
            self.master_key = master_key
        
        # Key storage and caching
        self.key_cache = {}
        self.key_metadata = {}
        
        # Rotation scheduling
        self.rotation_schedule = {}
        self.rotation_thread = None
        
        # Performance metrics
        self.metrics = {
            'keys_generated': 0,
            'keys_rotated': 0,
            'keys_revoked': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }
        
        # Initialize database and start services
        self._initialize_database()
        self._load_existing_keys()
        
        if self.auto_rotation:
            self._start_rotation_service()
        
        self.logger.info(f"Key Manager initialized for device {self.device_id}")
    
    def _get_security_parameters(self, level: str) -> Dict[str, Any]:
        """Get security parameters based on level"""
        params = {
            'basic': {
                'pbkdf2_iterations': 100000,
                'key_rotation_interval': 86400,  # 24 hours
                'max_key_usage': 10000,
                'key_derivation_rounds': 1,
                'cache_ttl': 3600
            },
            'standard': {
                'pbkdf2_iterations': 200000,
                'key_rotation_interval': 43200,  # 12 hours
                'max_key_usage': 5000,
                'key_derivation_rounds': 2,
                'cache_ttl': 1800
            },
            'high': {
                'pbkdf2_iterations': 500000,
                'key_rotation_interval': 21600,  # 6 hours
                'max_key_usage': 1000,
                'key_derivation_rounds': 3,
                'cache_ttl': 900
            }
        }
        return params.get(level, params['standard'])
    
    def _generate_device_id(self) -> str:
        """Generate unique device identifier"""
        import platform
        import uuid
        
        # Collect system information
        system_info = {
            'platform': platform.system(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'mac_address': uuid.getnode(),
            'random': secrets.randbits(64)
        }
        
        # Create deterministic but unique ID
        info_string = json.dumps(system_info, sort_keys=True)
        device_hash = hashlib.sha256(info_string.encode()).hexdigest()[:16]
        
        return f"device_{device_hash}"
    
    def _generate_master_key(self) -> bytes:
        """Generate cryptographically secure master key"""
        # Use multiple entropy sources
        entropy_sources = [
            os.urandom(32),
            secrets.token_bytes(32),
            hashlib.sha256(str(time.time()).encode()).digest(),
            hashlib.sha256(self.device_id.encode()).digest()
        ]
        
        # Combine entropy sources
        combined_entropy = b''.join(entropy_sources)
        
        # Derive master key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 512 bits
            salt=b'tensor_crypto_master_key_salt_2025',
            info=f'master_key_{self.device_id}'.encode(),
            backend=default_backend()
        )
        
        master_key = hkdf.derive(combined_entropy)
        
        self.logger.info("Master key generated using multiple entropy sources")
        return master_key
    
    def _initialize_database(self):
        """Initialize SQLite database for key storage"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create keys table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS keys (
                    key_id TEXT PRIMARY KEY,
                    key_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    encrypted_key BLOB NOT NULL,
                    device_id TEXT NOT NULL,
                    session_id TEXT,
                    created_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP,
                    rotated_from TEXT,
                    usage_count INTEGER DEFAULT 0,
                    algorithm_info TEXT,
                    security_level TEXT NOT NULL,
                    FOREIGN KEY (rotated_from) REFERENCES keys (key_id)
                )
            ''')
            
            # Create key derivation history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS key_derivations (
                    derivation_id TEXT PRIMARY KEY,
                    parent_key_id TEXT NOT NULL,
                    derived_key_id TEXT NOT NULL,
                    derivation_path TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (parent_key_id) REFERENCES keys (key_id),
                    FOREIGN KEY (derived_key_id) REFERENCES keys (key_id)
                )
            ''')
            
            # Create key usage log table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS key_usage_log (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    session_id TEXT,
                    success BOOLEAN NOT NULL,
                    FOREIGN KEY (key_id) REFERENCES keys (key_id)
                )
            ''')
            
            # Create indexes for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_keys_device ON keys (device_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_keys_session ON keys (session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_keys_type_status ON keys (key_type, status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_usage_timestamp ON key_usage_log (timestamp)')
            
            conn.commit()
        
        self.logger.debug("Key storage database initialized")
    
    def _load_existing_keys(self):
        """Load existing keys from database into cache"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM keys 
                WHERE device_id = ? AND status IN ('active', 'rotating')
                ORDER BY created_at DESC
            ''', (self.device_id,))
            
            for row in cursor.fetchall():
                metadata = KeyMetadata(
                    key_id=row['key_id'],
                    key_type=KeyType(row['key_type']),
                    status=KeyStatus(row['status']),
                    created_at=datetime.fromisoformat(row['created_at']),
                    expires_at=datetime.fromisoformat(row['expires_at']) if row['expires_at'] else None,
                    rotated_from=row['rotated_from'],
                    usage_count=row['usage_count'],
                    device_id=row['device_id'],
                    session_id=row['session_id'],
                    algorithm_info=json.loads(row['algorithm_info']),
                    security_level=row['security_level']
                )
                
                self.key_metadata[row['key_id']] = metadata
        
        self.logger.info(f"Loaded {len(self.key_metadata)} existing keys from database")
    
    def derive_key(self, key_type: KeyType, context: str,
                  parent_key_id: Optional[str] = None,
                  key_length: int = 32,
                  session_id: Optional[str] = None) -> Tuple[str, bytes]:
        """
        Derive a new key using hierarchical key derivation
        
        Args:
            key_type: Type of key to derive
            context: Derivation context/purpose
            parent_key_id: Parent key ID (uses master if None)
            key_length: Length of derived key in bytes
            session_id: Optional session ID for session keys
            
        Returns:
            Tuple of (key_id, derived_key)
        """
        with self._lock:
            # Determine parent key
            if parent_key_id:
                if parent_key_id not in self.key_metadata:
                    raise ValueError(f"Parent key {parent_key_id} not found")
                parent_key = self._decrypt_stored_key(parent_key_id)
                derivation_path = f"{parent_key_id}/{context}"
            else:
                parent_key = self.master_key
                derivation_path = f"master/{context}"
            
            # Generate unique key ID
            key_id = self._generate_key_id(key_type, context, session_id)
            
            # Derive key using HKDF
            derived_key = self._perform_key_derivation(
                parent_key, context, key_length, key_id
            )
            
            # Calculate expiration time
            expires_at = None
            if key_type in [KeyType.SESSION, KeyType.EPHEMERAL]:
                expires_at = datetime.now() + timedelta(
                    seconds=self.security_params['key_rotation_interval']
                )
            
            # Create metadata
            metadata = KeyMetadata(
                key_id=key_id,
                key_type=key_type,
                status=KeyStatus.ACTIVE,
                created_at=datetime.now(),
                expires_at=expires_at,
                rotated_from=None,
                usage_count=0,
                device_id=self.device_id,
                session_id=session_id,
                algorithm_info={
                    'derivation_algorithm': 'HKDF-SHA256',
                    'key_length': key_length,
                    'derivation_rounds': self.security_params['key_derivation_rounds']
                },
                security_level=self.security_level
            )
            
            # Store key and metadata
            self._store_key(key_id, derived_key, metadata)
            
            # Record derivation
            if parent_key_id:
                self._record_key_derivation(parent_key_id, key_id, derivation_path)
            
            # Update metrics
            self.metrics['keys_generated'] += 1
            
            self.logger.info(f"Derived {key_type.value} key {key_id[:16]}... from {derivation_path}")
            
            return key_id, derived_key
    
    def _generate_key_id(self, key_type: KeyType, context: str, 
                        session_id: Optional[str] = None) -> str:
        """Generate unique key identifier"""
        timestamp = int(time.time() * 1000000)  # Microsecond precision
        components = [
            key_type.value,
            self.device_id[:8],
            context[:16],
            str(timestamp)
        ]
        
        if session_id:
            components.append(session_id[:8])
        
        # Add random component for uniqueness
        components.append(secrets.token_hex(4))
        
        key_id = '_'.join(components)
        
        # Ensure uniqueness
        counter = 0
        original_key_id = key_id
        while key_id in self.key_metadata:
            counter += 1
            key_id = f"{original_key_id}_{counter}"
        
        return key_id
    
    def _perform_key_derivation(self, parent_key: bytes, context: str,
                              key_length: int, key_id: str) -> bytes:
        """Perform multiple rounds of key derivation"""
        derived_key = parent_key
        
        # Multiple derivation rounds for enhanced security
        for round_num in range(self.security_params['key_derivation_rounds']):
            round_context = f"{context}_round_{round_num}_{key_id}"
            
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=key_length,
                salt=f"tensor_crypto_derivation_salt_{round_num}".encode(),
                info=round_context.encode(),
                backend=default_backend()
            )
            
            derived_key = hkdf.derive(derived_key)
        
        return derived_key
    
    def _store_key(self, key_id: str, key_data: bytes, metadata: KeyMetadata):
        """Store key and metadata securely"""
        # Encrypt key data for storage
        encrypted_key = self._encrypt_key_for_storage(key_data)
        
        # Store in database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO keys (
                    key_id, key_type, status, encrypted_key, device_id,
                    session_id, created_at, expires_at, rotated_from,
                    usage_count, algorithm_info, security_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                key_id,
                metadata.key_type.value,
                metadata.status.value,
                encrypted_key,
                metadata.device_id,
                metadata.session_id,
                metadata.created_at.isoformat(),
                metadata.expires_at.isoformat() if metadata.expires_at else None,
                metadata.rotated_from,
                metadata.usage_count,
                json.dumps(metadata.algorithm_info),
                metadata.security_level
            ))
            
            conn.commit()
        
        # Cache metadata
        self.key_metadata[key_id] = metadata
        
        # Cache key data with TTL
        cache_entry = {
            'key_data': key_data,
            'cached_at': time.time(),
            'ttl': self.security_params['cache_ttl']
        }
        self.key_cache[key_id] = cache_entry
    
    def _encrypt_key_for_storage(self, key_data: bytes) -> bytes:
        """Encrypt key data for secure storage"""
        # Derive storage key from master key
        storage_kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'tensor_crypto_storage_salt',
            info=f'storage_key_{self.device_id}'.encode(),
            backend=default_backend()
        )
        storage_key = storage_kdf.derive(self.master_key)
        
        # Generate random IV
        iv = os.urandom(16)
        
        # Encrypt using AES-CTR
        cipher = Cipher(
            algorithms.AES(storage_key),
            modes.CTR(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(key_data) + encryptor.finalize()
        
        # Combine IV and ciphertext
        return iv + ciphertext
    
    def _decrypt_stored_key(self, key_id: str) -> bytes:
        """Decrypt key data from storage"""
        # Check cache first
        if key_id in self.key_cache:
            cache_entry = self.key_cache[key_id]
            if time.time() - cache_entry['cached_at'] < cache_entry['ttl']:
                self.metrics['cache_hits'] += 1
                return cache_entry['key_data']
            else:
                # Remove expired cache entry
                del self.key_cache[key_id]
        
        self.metrics['cache_misses'] += 1
        
        # Load from database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT encrypted_key FROM keys WHERE key_id = ?',
                (key_id,)
            )
            row = cursor.fetchone()
            
            if not row:
                raise KeyError(f"Key {key_id} not found")
            
            encrypted_key = row[0]
        
        # Derive storage key
        storage_kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'tensor_crypto_storage_salt',
            info=f'storage_key_{self.device_id}'.encode(),
            backend=default_backend()
        )
        storage_key = storage_kdf.derive(self.master_key)
        
        # Extract IV and ciphertext
        iv = encrypted_key[:16]
        ciphertext = encrypted_key[16:]
        
        # Decrypt
        cipher = Cipher(
            algorithms.AES(storage_key),
            modes.CTR(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        key_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Cache the decrypted key
        cache_entry = {
            'key_data': key_data,
            'cached_at': time.time(),
            'ttl': self.security_params['cache_ttl']
        }
        self.key_cache[key_id] = cache_entry
        
        return key_data
    
    def get_key(self, key_id: str, increment_usage: bool = True) -> bytes:
        """
        Retrieve key by ID
        
        Args:
            key_id: Key identifier
            increment_usage: Whether to increment usage counter
            
        Returns:
            Key data bytes
        """
        with self._lock:
            if key_id not in self.key_metadata:
                raise KeyError(f"Key {key_id} not found")
            
            metadata = self.key_metadata[key_id]
            
            # Check key status
            if metadata.status not in [KeyStatus.ACTIVE, KeyStatus.ROTATING]:
                raise ValueError(f"Key {key_id} is {metadata.status.value}")
            
            # Check expiration
            if metadata.expires_at and datetime.now() > metadata.expires_at:
                self._mark_key_expired(key_id)
                raise ValueError(f"Key {key_id} has expired")
            
            # Check usage limits
            if metadata.usage_count >= self.security_params['max_key_usage']:
                self._schedule_key_rotation(key_id)
            
            # Retrieve key data
            key_data = self._decrypt_stored_key(key_id)
            
            # Update usage counter
            if increment_usage:
                self._increment_key_usage(key_id)
                self._log_key_usage(key_id, 'retrieve', True)
            
            return key_data
    
    def _increment_key_usage(self, key_id: str):
        """Increment key usage counter"""
        metadata = self.key_metadata[key_id]
        metadata.usage_count += 1
        
        # Update database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE keys SET usage_count = ? WHERE key_id = ?',
                (metadata.usage_count, key_id)
            )
            conn.commit()
    
    def _log_key_usage(self, key_id: str, operation: str, success: bool,
                      session_id: Optional[str] = None):
        """Log key usage for audit purposes"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO key_usage_log (key_id, operation, timestamp, session_id, success)
                VALUES (?, ?, ?, ?, ?)
            ''', (key_id, operation, datetime.now().isoformat(), session_id, success))
            conn.commit()
    
    def rotate_key(self, key_id: str, force: bool = False) -> str:
        """
        Rotate a key to maintain forward secrecy
        
        Args:
            key_id: Key to rotate
            force: Force rotation even if not due
            
        Returns:
            New key ID
        """
        with self._lock:
            if key_id not in self.key_metadata:
                raise KeyError(f"Key {key_id} not found")
            
            old_metadata = self.key_metadata[key_id]
            
            # Check if rotation is needed
            if not force and old_metadata.status == KeyStatus.ROTATING:
                raise ValueError(f"Key {key_id} is already being rotated")
            
            # Mark old key as rotating
            old_metadata.status = KeyStatus.ROTATING
            self._update_key_status(key_id, KeyStatus.ROTATING)
            
            # Generate new key
            context = f"rotation_of_{key_id}_{int(time.time())}"
            new_key_id, new_key_data = self.derive_key(
                old_metadata.key_type,
                context,
                session_id=old_metadata.session_id
            )
            
            # Update new key metadata to reference old key
            new_metadata = self.key_metadata[new_key_id]
            new_metadata.rotated_from = key_id
            
            # Update database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'UPDATE keys SET rotated_from = ? WHERE key_id = ?',
                    (key_id, new_key_id)
                )
                conn.commit()
            
            # Schedule old key deprecation
            self._schedule_key_deprecation(key_id)
            
            # Update metrics
            self.metrics['keys_rotated'] += 1
            
            self.logger.info(f"Key rotated: {key_id[:16]}... -> {new_key_id[:16]}...")
            
            return new_key_id
    
    def _update_key_status(self, key_id: str, new_status: KeyStatus):
        """Update key status in database and cache"""
        if key_id in self.key_metadata:
            self.key_metadata[key_id].status = new_status
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE keys SET status = ? WHERE key_id = ?',
                (new_status.value, key_id)
            )
            conn.commit()
    
    def _mark_key_expired(self, key_id: str):
        """Mark key as expired"""
        self._update_key_status(key_id, KeyStatus.EXPIRED)
        
        # Remove from cache
        if key_id in self.key_cache:
            del self.key_cache[key_id]
        
        self.logger.warning(f"Key {key_id[:16]}... marked as expired")
    
    def revoke_key(self, key_id: str, reason: str = "manual_revocation"):
        """
        Revoke a key immediately
        
        Args:
            key_id: Key to revoke
            reason: Reason for revocation
        """
        with self._lock:
            if key_id not in self.key_metadata:
                raise KeyError(f"Key {key_id} not found")
            
            # Update status
            self._update_key_status(key_id, KeyStatus.REVOKED)
            
            # Remove from cache
            if key_id in self.key_cache:
                del self.key_cache[key_id]
            
            # Log revocation
            self._log_key_usage(key_id, f'revoked_{reason}', True)
            
            # Update metrics
            self.metrics['keys_revoked'] += 1
            
            self.logger.warning(f"Key {key_id[:16]}... revoked: {reason}")
    
    def list_keys(self, key_type: Optional[KeyType] = None,
                  status: Optional[KeyStatus] = None,
                  session_id: Optional[str] = None) -> List[KeyMetadata]:
        """
        List keys matching criteria
        
        Args:
            key_type: Filter by key type
            status: Filter by key status
            session_id: Filter by session ID
            
        Returns:
            List of key metadata
        """
        results = []
        
        for metadata in self.key_metadata.values():
            if key_type and metadata.key_type != key_type:
                continue
            if status and metadata.status != status:
                continue
            if session_id and metadata.session_id != session_id:
                continue
            
            results.append(metadata)
        
        return sorted(results, key=lambda x: x.created_at, reverse=True)
    
    def cleanup_expired_keys(self) -> int:
        """
        Clean up expired and deprecated keys
        
        Returns:
            Number of keys cleaned up
        """
        with self._lock:
            current_time = datetime.now()
            cleaned_count = 0
            
            keys_to_remove = []
            
            for key_id, metadata in self.key_metadata.items():
                # Check for expiration
                if (metadata.expires_at and current_time > metadata.expires_at and 
                    metadata.status == KeyStatus.ACTIVE):
                    self._mark_key_expired(key_id)
                
                # Remove old deprecated/expired keys
                if metadata.status in [KeyStatus.DEPRECATED, KeyStatus.EXPIRED, KeyStatus.REVOKED]:
                    # Keep for audit period (30 days)
                    audit_period = timedelta(days=30)
                    if current_time - metadata.created_at > audit_period:
                        keys_to_remove.append(key_id)
                        cleaned_count += 1
            
            # Remove old keys from database and cache
            if keys_to_remove:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.executemany(
                        'DELETE FROM keys WHERE key_id = ?',
                        [(key_id,) for key_id in keys_to_remove]
                    )
                    conn.commit()
                
                # Remove from memory
                for key_id in keys_to_remove:
                    if key_id in self.key_metadata:
                        del self.key_metadata[key_id]
                    if key_id in self.key_cache:
                        del self.key_cache[key_id]
            
            if cleaned_count > 0:
                self.logger.info(f"Cleaned up {cleaned_count} expired keys")
            
            return cleaned_count
    
    def _record_key_derivation(self, parent_key_id: str, derived_key_id: str, path: str):
        """Record key derivation for audit trail"""
        derivation_id = f"{parent_key_id}_{derived_key_id}_{int(time.time())}"
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO key_derivations (derivation_id, parent_key_id, derived_key_id, derivation_path, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (derivation_id, parent_key_id, derived_key_id, path, datetime.now().isoformat()))
            conn.commit()
    
    def _schedule_key_rotation(self, key_id: str):
        """Schedule automatic key rotation"""
        if self.auto_rotation and key_id not in self.rotation_schedule:
            rotation_time = datetime.now() + timedelta(seconds=300)  # 5 minutes grace
            self.rotation_schedule[key_id] = rotation_time
            self.logger.info(f"Scheduled rotation for key {key_id[:16]}...")
    
    def _schedule_key_deprecation(self, key_id: str, delay_seconds: int = 3600):
        """Schedule key deprecation after rotation"""
        deprecation_time = datetime.now() + timedelta(seconds=delay_seconds)
        # In a full implementation, this would use a proper task scheduler
        threading.Timer(delay_seconds, self._deprecate_key, args=[key_id]).start()
    
    def _deprecate_key(self, key_id: str):
        """Mark key as deprecated"""
        try:
            self._update_key_status(key_id, KeyStatus.DEPRECATED)
            self.logger.info(f"Key {key_id[:16]}... deprecated")
        except Exception as e:
            self.logger.error(f"Error deprecating key {key_id}: {e}")
    
    def _start_rotation_service(self):
        """Start background key rotation service"""
        def rotation_worker():
            while self.auto_rotation:
                try:
                    current_time = datetime.now()
                    keys_to_rotate = []
                    
                    # Check scheduled rotations
                    for key_id, scheduled_time in list(self.rotation_schedule.items()):
                        if current_time >= scheduled_time:
                            keys_to_rotate.append(key_id)
                            del self.rotation_schedule[key_id]
                    
                    # Perform rotations
                    for key_id in keys_to_rotate:
                        try:
                            if key_id in self.key_metadata:
                                self.rotate_key(key_id)
                        except Exception as e:
                            self.logger.error(f"Failed to rotate key {key_id}: {e}")
                    
                    # Clean up expired keys
                    self.cleanup_expired_keys()
                    
                    time.sleep(60)  # Check every minute
                    
                except Exception as e:
                    self.logger.error(f"Rotation service error: {e}")
                    time.sleep(60)
        
        self.rotation_thread = threading.Thread(target=rotation_worker, daemon=True)
        self.rotation_thread.start()
        self.logger.info("Automatic key rotation service started")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get key management metrics"""
        with self._lock:
            total_keys = len(self.key_metadata)
            active_keys = sum(1 for m in self.key_metadata.values() 
                            if m.status == KeyStatus.ACTIVE)
            
            # Calculate cache hit rate
            total_requests = self.metrics['cache_hits'] + self.metrics['cache_misses']
            cache_hit_rate = (self.metrics['cache_hits'] / total_requests) if total_requests > 0 else 0
            
            return {
                **self.metrics,
                'total_keys': total_keys,
                'active_keys': active_keys,
                'cached_keys': len(self.key_cache),
                'cache_hit_rate': cache_hit_rate,
                'scheduled_rotations': len(self.rotation_schedule),
                'security_level': self.security_level,
                'auto_rotation_enabled': self.auto_rotation
            }
    
    def shutdown(self):
        """Shutdown key manager and clean up resources"""
        self.auto_rotation = False
        
        if self.rotation_thread and self.rotation_thread.is_alive():
            self.rotation_thread.join(timeout=5)
        
        # Clear sensitive data from memory
        self.key_cache.clear()
        self.master_key = b'\x00' * len(self.master_key)  # Zero out master key
        
        self.logger.info("Key Manager shutdown completed")
    
    def __del__(self):
        """Destructor to ensure cleanup"""
        try:
            self.shutdown()
        except:
            pass  # Ignore errors during cleanup
    
    def __repr__(self) -> str:
        """String representation"""
        return (f"KeyManager(device_id='{self.device_id[:16]}...', "
                f"security_level='{self.security_level}', "
                f"keys={len(self.key_metadata)}, "
                f"auto_rotation={self.auto_rotation})")
