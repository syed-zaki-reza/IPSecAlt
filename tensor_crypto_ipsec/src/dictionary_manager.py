"""
dictionary_manager.py
Dynamic Dictionary Management for Tensor-Based Post-Quantum Cryptography

This module implements secure, renewable shared dictionary systems with forward secrecy,
manufacturer-embedded provisioning, and advanced synchronization capabilities for
distributed cryptographic operations.
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
import pickle
import zlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union, Set
from dataclasses import dataclass, asdict
from enum import Enum
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ThreadPoolExecutor, as_completed


class DictionaryType(Enum):
    """Types of cryptographic dictionaries"""
    SHARED = "shared"
    SESSION = "session"
    EPHEMERAL = "ephemeral"
    MANUFACTURER = "manufacturer"
    BROADCAST = "broadcast"


class DictionaryStatus(Enum):
    """Dictionary lifecycle states"""
    ACTIVE = "active"
    PENDING = "pending"
    SYNCING = "syncing"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"
    EXPIRED = "expired"


class SyncStatus(Enum):
    """Synchronization status between devices"""
    IN_SYNC = "in_sync"
    OUT_OF_SYNC = "out_of_sync"
    SYNCING = "syncing"
    CONFLICT = "conflict"
    FAILED = "failed"


@dataclass
class DictionaryMetadata:
    """Metadata for dictionary instances"""
    dictionary_id: str
    dict_type: DictionaryType
    status: DictionaryStatus
    created_at: datetime
    expires_at: Optional[datetime]
    last_used: datetime
    usage_count: int
    size: int
    device_id: str
    session_id: Optional[str]
    peer_devices: Set[str]
    version: int
    checksum: str
    sync_status: SyncStatus
    encryption_params: Dict[str, Any]


class DynamicDictionaryManager:
    """
    Advanced dictionary management system for tensor-based cryptography
    
    Provides secure generation, distribution, synchronization, and lifecycle
    management of cryptographic dictionaries with forward secrecy guarantees.
    """
    
    def __init__(self, 
                 manufacturer_key: Optional[bytes] = None,
                 device_id: Optional[str] = None,
                 db_path: str = "dictionary_store.db",
                 security_level: str = 'standard',
                 auto_refresh: bool = True,
                 max_cache_size: int = 100):
        """
        Initialize dynamic dictionary manager
        
        Args:
            manufacturer_key: Pre-shared manufacturer key for device authentication
            device_id: Unique device identifier
            db_path: Path to dictionary storage database
            security_level: Security level ('basic', 'standard', 'high')
            auto_refresh: Enable automatic dictionary refresh
            max_cache_size: Maximum number of dictionaries to cache in memory
        """
        self.manufacturer_key = manufacturer_key or self._generate_manufacturer_key()
        self.device_id = device_id or self._generate_device_id()
        self.db_path = db_path
        self.security_level = security_level
        self.auto_refresh = auto_refresh
        self.max_cache_size = max_cache_size
        
        # Initialize logging
        self.logger = logging.getLogger(__name__)
        
        # Thread synchronization
        self._lock = threading.RLock()
        self._sync_lock = threading.Lock()
        
        # Security parameters
        self.security_params = self._get_security_parameters(security_level)
        
        # Dictionary storage and caching
        self.dictionary_cache = {}  # {dict_id: {dictionary, metadata, cached_at}}
        self.dictionary_metadata = {}  # {dict_id: DictionaryMetadata}
        
        # Synchronization tracking
        self.sync_sessions = {}
        self.pending_syncs = set()
        
        # Performance metrics
        self.metrics = {
            'dictionaries_generated': 0,
            'dictionaries_refreshed': 0,
            'sync_operations': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'lookup_operations': 0,
            'failed_syncs': 0
        }
        
        # Background services
        self.refresh_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="dict_refresh")
        self.sync_executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="dict_sync")
        
        # Initialize database and load existing dictionaries
        self._initialize_database()
        self._load_existing_dictionaries()
        
        # Start background services
        if self.auto_refresh:
            self._start_refresh_service()
        
        self.logger.info(f"Dictionary Manager initialized for device {self.device_id}")
    
    def _get_security_parameters(self, level: str) -> Dict[str, Any]:
        """Get security parameters based on level"""
        params = {
            'basic': {
                'refresh_interval': 3600,  # 1 hour
                'dictionary_size': 1024,
                'pbkdf2_iterations': 100000,
                'max_usage_count': 10000,
                'cache_ttl': 1800,
                'sync_timeout': 30,
                'max_entry_size': 64
            },
            'standard': {
                'refresh_interval': 1800,  # 30 minutes
                'dictionary_size': 2048,
                'pbkdf2_iterations': 200000,
                'max_usage_count': 5000,
                'cache_ttl': 900,
                'sync_timeout': 60,
                'max_entry_size': 128
            },
            'high': {
                'refresh_interval': 900,   # 15 minutes
                'dictionary_size': 4096,
                'pbkdf2_iterations': 500000,
                'max_usage_count': 1000,
                'cache_ttl': 300,
                'sync_timeout': 120,
                'max_entry_size': 256
            }
        }
        return params.get(level, params['standard'])
    
    def _generate_manufacturer_key(self) -> bytes:
        """Generate manufacturer key for device authentication"""
        # In real implementation, this would be provisioned by manufacturer
        entropy = os.urandom(64) + str(time.time()).encode()
        
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=b'tensor_crypto_manufacturer_salt_2025',
            info=b'manufacturer_root_key',
            backend=default_backend()
        )
        
        return kdf.derive(entropy)
    
    def _generate_device_id(self) -> str:
        """Generate unique device identifier"""
        import platform
        import uuid
        
        # Collect hardware-specific information
        hardware_info = {
            'platform': platform.system(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'mac_address': uuid.getnode(),
            'boot_time': time.time(),
            'random': secrets.randbits(128)
        }
        
        # Create deterministic device ID
        info_json = json.dumps(hardware_info, sort_keys=True)
        device_hash = hashlib.sha256(info_json.encode()).hexdigest()[:24]
        
        return f"dict_device_{device_hash}"
    
    def _initialize_database(self):
        """Initialize SQLite database for dictionary storage"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Main dictionary table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS dictionaries (
                    dictionary_id TEXT PRIMARY KEY,
                    dict_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    encrypted_data BLOB NOT NULL,
                    metadata_json TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    session_id TEXT,
                    created_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP,
                    last_used TIMESTAMP NOT NULL,
                    usage_count INTEGER DEFAULT 0,
                    size INTEGER NOT NULL,
                    version INTEGER DEFAULT 1,
                    checksum TEXT NOT NULL,
                    sync_status TEXT NOT NULL
                )
            ''')
            
            # Dictionary sharing relationships
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS dictionary_peers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dictionary_id TEXT NOT NULL,
                    peer_device_id TEXT NOT NULL,
                    shared_at TIMESTAMP NOT NULL,
                    last_sync TIMESTAMP,
                    sync_version INTEGER DEFAULT 1,
                    FOREIGN KEY (dictionary_id) REFERENCES dictionaries (dictionary_id),
                    UNIQUE(dictionary_id, peer_device_id)
                )
            ''')
            
            # Synchronization log
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sync_log (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dictionary_id TEXT NOT NULL,
                    peer_device_id TEXT NOT NULL,
                    sync_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TIMESTAMP NOT NULL,
                    completed_at TIMESTAMP,
                    error_message TEXT,
                    bytes_transferred INTEGER,
                    FOREIGN KEY (dictionary_id) REFERENCES dictionaries (dictionary_id)
                )
            ''')
            
            # Dictionary usage log
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS dictionary_usage (
                    usage_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dictionary_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    lookup_key TEXT,
                    timestamp TIMESTAMP NOT NULL,
                    session_id TEXT,
                    success BOOLEAN NOT NULL,
                    FOREIGN KEY (dictionary_id) REFERENCES dictionaries (dictionary_id)
                )
            ''')
            
            # Create indexes for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_dict_device_session ON dictionaries (device_id, session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_dict_status ON dictionaries (status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_dict_expires ON dictionaries (expires_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_peers_dict ON dictionary_peers (dictionary_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_usage_timestamp ON dictionary_usage (timestamp)')
            
            conn.commit()
        
        self.logger.debug("Dictionary storage database initialized")
    
    def _load_existing_dictionaries(self):
        """Load existing dictionary metadata from database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT d.*, GROUP_CONCAT(p.peer_device_id) as peer_devices
                FROM dictionaries d
                LEFT JOIN dictionary_peers p ON d.dictionary_id = p.dictionary_id
                WHERE d.device_id = ? AND d.status IN ('active', 'pending', 'syncing')
                GROUP BY d.dictionary_id
                ORDER BY d.created_at DESC
            ''', (self.device_id,))
            
            for row in cursor.fetchall():
                peer_devices = set(row['peer_devices'].split(',')) if row['peer_devices'] else set()
                
                metadata = DictionaryMetadata(
                    dictionary_id=row['dictionary_id'],
                    dict_type=DictionaryType(row['dict_type']),
                    status=DictionaryStatus(row['status']),
                    created_at=datetime.fromisoformat(row['created_at']),
                    expires_at=datetime.fromisoformat(row['expires_at']) if row['expires_at'] else None,
                    last_used=datetime.fromisoformat(row['last_used']),
                    usage_count=row['usage_count'],
                    size=row['size'],
                    device_id=row['device_id'],
                    session_id=row['session_id'],
                    peer_devices=peer_devices,
                    version=row['version'],
                    checksum=row['checksum'],
                    sync_status=SyncStatus(row['sync_status']),
                    encryption_params=json.loads(row['metadata_json'])
                )
                
                self.dictionary_metadata[row['dictionary_id']] = metadata
        
        self.logger.info(f"Loaded {len(self.dictionary_metadata)} existing dictionaries")
    
    def generate_shared_dictionary(self, 
                                 peer_device_id: str,
                                 session_id: str,
                                 dict_type: DictionaryType = DictionaryType.SHARED,
                                 size: Optional[int] = None,
                                 custom_entropy: Optional[bytes] = None) -> Tuple[str, Dict[int, bytes]]:
        """
        Generate shared dictionary for secure communication
        
        Args:
            peer_device_id: ID of peer device to share with
            session_id: Session identifier for scoping
            dict_type: Type of dictionary to generate
            size: Dictionary size (uses security param default if None)
            custom_entropy: Additional entropy for generation
            
        Returns:
            Tuple of (dictionary_id, dictionary_data)
        """
        with self._lock:
            if size is None:
                size = self.security_params['dictionary_size']
            
            # Create deterministic seed for both devices
            device_pair = tuple(sorted([self.device_id, peer_device_id]))
            seed_components = [
                device_pair[0],
                device_pair[1],
                session_id,
                dict_type.value,
                str(int(time.time() // self.security_params['refresh_interval']))  # Refresh period
            ]
            
            if custom_entropy:
                seed_components.append(custom_entropy.hex())
            
            combined_seed = '_'.join(seed_components)
            
            # Derive dictionary generation key
            dict_key = self._derive_dictionary_key(combined_seed)
            
            # Generate dictionary ID
            dict_id = self._generate_dictionary_id(dict_type, session_id, peer_device_id)
            
            # Generate dictionary content
            dictionary = self._generate_dictionary_content(dict_key, size)
            
            # Calculate checksum
            checksum = self._calculate_dictionary_checksum(dictionary)
            
            # Create metadata
            expires_at = None
            if dict_type in [DictionaryType.SESSION, DictionaryType.EPHEMERAL]:
                expires_at = datetime.now() + timedelta(seconds=self.security_params['refresh_interval'])
            
            metadata = DictionaryMetadata(
                dictionary_id=dict_id,
                dict_type=dict_type,
                status=DictionaryStatus.ACTIVE,
                created_at=datetime.now(),
                expires_at=expires_at,
                last_used=datetime.now(),
                usage_count=0,
                size=size,
                device_id=self.device_id,
                session_id=session_id,
                peer_devices={peer_device_id},
                version=1,
                checksum=checksum,
                sync_status=SyncStatus.IN_SYNC,
                encryption_params={
                    'algorithm': 'AES-CTR',
                    'key_derivation': 'PBKDF2-HMAC-SHA256',
                    'iterations': self.security_params['pbkdf2_iterations']
                }
            )
            
            # Store dictionary
            self._store_dictionary(dict_id, dictionary, metadata)
            
            # Record peer relationship
            self._record_peer_relationship(dict_id, peer_device_id)
            
            # Update metrics
            self.metrics['dictionaries_generated'] += 1
            
            self.logger.info(f"Generated shared dictionary {dict_id[:16]}... "
                           f"({size} entries) for session {session_id}")
            
            return dict_id, dictionary
    
    def _derive_dictionary_key(self, seed: str) -> bytes:
        """Derive dictionary generation key from seed"""
        # Use manufacturer key as base key material
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,
            salt=b'tensor_crypto_dictionary_salt_2025',
            iterations=self.security_params['pbkdf2_iterations']
        )
        
        # Combine manufacturer key with seed
        combined_input = self.manufacturer_key + seed.encode()
        derived_key = kdf.derive(combined_input)
        
        return derived_key
    
    def _generate_dictionary_id(self, dict_type: DictionaryType, 
                              session_id: str, peer_device_id: str) -> str:
        """Generate unique dictionary identifier"""
        timestamp = int(time.time() * 1000000)  # Microsecond precision
        components = [
            dict_type.value,
            self.device_id[:8],
            peer_device_id[:8],
            session_id[:16],
            str(timestamp),
            secrets.token_hex(4)
        ]
        
        dict_id = '_'.join(components)
        
        # Ensure uniqueness
        counter = 0
        original_id = dict_id
        while dict_id in self.dictionary_metadata:
            counter += 1
            dict_id = f"{original_id}_{counter}"
        
        return dict_id
    
    def _generate_dictionary_content(self, generation_key: bytes, size: int) -> Dict[int, bytes]:
        """Generate dictionary content using cryptographic key"""
        # Use generation key to seed deterministic random generator
        np.random.seed(int.from_bytes(generation_key[:4], 'big'))
        
        dictionary = {}
        max_entry_size = self.security_params['max_entry_size']
        
        # Generate unique keys and values
        used_keys = set()
        
        for _ in range(size):
            # Generate unique key
            while True:
                key = np.random.randint(0, 2**24, dtype=np.uint32)  # 24-bit keys
                if key not in used_keys:
                    used_keys.add(key)
                    break
            
            # Generate random value
            value_size = np.random.randint(16, max_entry_size + 1)
            value = np.random.bytes(value_size)
            
            dictionary[int(key)] = value
        
        return dictionary
    
    def _calculate_dictionary_checksum(self, dictionary: Dict[int, bytes]) -> str:
        """Calculate checksum for dictionary integrity verification"""
        # Serialize dictionary in deterministic order
        serialized_items = []
        for key in sorted(dictionary.keys()):
            serialized_items.append(f"{key}:{dictionary[key].hex()}")
        
        serialized_dict = '|'.join(serialized_items)
        checksum = hashlib.sha256(serialized_dict.encode()).hexdigest()
        
        return checksum
    
    def _store_dictionary(self, dict_id: str, dictionary: Dict[int, bytes], 
                         metadata: DictionaryMetadata):
        """Store dictionary and metadata securely"""
        # Encrypt dictionary for storage
        encrypted_data = self._encrypt_dictionary_for_storage(dictionary)
        
        # Store in database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO dictionaries (
                    dictionary_id, dict_type, status, encrypted_data, metadata_json,
                    device_id, session_id, created_at, expires_at, last_used,
                    usage_count, size, version, checksum, sync_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                dict_id,
                metadata.dict_type.value,
                metadata.status.value,
                encrypted_data,
                json.dumps(metadata.encryption_params),
                metadata.device_id,
                metadata.session_id,
                metadata.created_at.isoformat(),
                metadata.expires_at.isoformat() if metadata.expires_at else None,
                metadata.last_used.isoformat(),
                metadata.usage_count,
                metadata.size,
                metadata.version,
                metadata.checksum,
                metadata.sync_status.value
            ))
            
            conn.commit()
        
        # Cache metadata
        self.dictionary_metadata[dict_id] = metadata
        
        # Cache dictionary with TTL
        cache_entry = {
            'dictionary': dictionary,
            'metadata': metadata,
            'cached_at': time.time(),
            'ttl': self.security_params['cache_ttl']
        }
        
        # Manage cache size
        if len(self.dictionary_cache) >= self.max_cache_size:
            self._evict_oldest_cache_entry()
        
        self.dictionary_cache[dict_id] = cache_entry
    
    def _encrypt_dictionary_for_storage(self, dictionary: Dict[int, bytes]) -> bytes:
        """Encrypt dictionary for secure storage"""
        # Serialize dictionary
        serialized_dict = pickle.dumps(dictionary)
        
        # Compress for efficiency
        compressed_dict = zlib.compress(serialized_dict, level=6)
        
        # Derive storage encryption key
        storage_key = self._derive_storage_key()
        
        # Generate random IV
        iv = os.urandom(16)
        
        # Encrypt using AES-CTR
        cipher = Cipher(
            algorithms.AES(storage_key),
            modes.CTR(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(compressed_dict) + encryptor.finalize()
        
        # Combine IV and ciphertext
        return iv + ciphertext
    
    def _decrypt_stored_dictionary(self, encrypted_data: bytes) -> Dict[int, bytes]:
        """Decrypt dictionary from storage"""
        # Extract IV and ciphertext
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Derive storage encryption key
        storage_key = self._derive_storage_key()
        
        # Decrypt
        cipher = Cipher(
            algorithms.AES(storage_key),
            modes.CTR(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        compressed_dict = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Decompress and deserialize
        serialized_dict = zlib.decompress(compressed_dict)
        dictionary = pickle.loads(serialized_dict)
        
        return dictionary
    
    def _derive_storage_key(self) -> bytes:
        """Derive key for encrypting dictionary storage"""
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'tensor_crypto_storage_salt',
            info=f'dictionary_storage_{self.device_id}'.encode(),
            backend=default_backend()
        )
        
        return kdf.derive(self.manufacturer_key)
    
    def get_dictionary(self, dictionary_id: str, 
                      auto_refresh: bool = True) -> Optional[Dict[int, bytes]]:
        """
        Retrieve dictionary by ID
        
        Args:
            dictionary_id: Dictionary identifier
            auto_refresh: Whether to automatically refresh expired dictionaries
            
        Returns:
            Dictionary data or None if not found/expired
        """
        with self._lock:
            if dictionary_id not in self.dictionary_metadata:
                return None
            
            metadata = self.dictionary_metadata[dictionary_id]
            
            # Check expiration
            if metadata.expires_at and datetime.now() > metadata.expires_at:
                if auto_refresh and metadata.dict_type in [DictionaryType.SESSION, DictionaryType.SHARED]:
                    self.logger.info(f"Auto-refreshing expired dictionary {dictionary_id[:16]}...")
                    return self._refresh_dictionary(dictionary_id)
                else:
                    self._mark_dictionary_expired(dictionary_id)
                    return None
            
            # Check cache first
            if dictionary_id in self.dictionary_cache:
                cache_entry = self.dictionary_cache[dictionary_id]
                if time.time() - cache_entry['cached_at'] < cache_entry['ttl']:
                    self.metrics['cache_hits'] += 1
                    self._update_usage_stats(dictionary_id)
                    return cache_entry['dictionary']
                else:
                    # Remove expired cache entry
                    del self.dictionary_cache[dictionary_id]
            
            self.metrics['cache_misses'] += 1
            
            # Load from database
            dictionary = self._load_dictionary_from_database(dictionary_id)
            
            if dictionary:
                # Cache the loaded dictionary
                cache_entry = {
                    'dictionary': dictionary,
                    'metadata': metadata,
                    'cached_at': time.time(),
                    'ttl': self.security_params['cache_ttl']
                }
                self.dictionary_cache[dictionary_id] = cache_entry
                
                self._update_usage_stats(dictionary_id)
                return dictionary
            
            return None
    
    def _load_dictionary_from_database(self, dictionary_id: str) -> Optional[Dict[int, bytes]]:
        """Load dictionary from database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT encrypted_data FROM dictionaries WHERE dictionary_id = ?',
                (dictionary_id,)
            )
            row = cursor.fetchone()
            
            if not row:
                return None
            
            encrypted_data = row[0]
        
        try:
            dictionary = self._decrypt_stored_dictionary(encrypted_data)
            return dictionary
        except Exception as e:
            self.logger.error(f"Failed to decrypt dictionary {dictionary_id}: {e}")
            return None
    
    def dictionary_lookup(self, dictionary_id: str, lookup_key: int, 
                         session_id: Optional[str] = None) -> Optional[bytes]:
        """
        Look up value in dictionary
        
        Args:
            dictionary_id: Dictionary identifier
            lookup_key: Key to look up
            session_id: Optional session ID for logging
            
        Returns:
            Value bytes or None if not found
        """
        dictionary = self.get_dictionary(dictionary_id)
        
        if dictionary is None:
            self._log_dictionary_usage(dictionary_id, 'lookup_failed', 
                                     str(lookup_key), session_id, False)
            return None
        
        value = dictionary.get(lookup_key)
        success = value is not None
        
        # Log usage
        self._log_dictionary_usage(dictionary_id, 'lookup', 
                                 str(lookup_key), session_id, success)
        
        self.metrics['lookup_operations'] += 1
        
        return value
    
    def refresh_dictionary(self, dictionary_id: str, 
                          force: bool = False) -> Optional[Dict[int, bytes]]:
        """
        Refresh dictionary for forward secrecy
        
        Args:
            dictionary_id: Dictionary to refresh
            force: Force refresh even if not expired
            
        Returns:
            New dictionary data or None if failed
        """
        if dictionary_id not in self.dictionary_metadata:
            return None
        
        metadata = self.dictionary_metadata[dictionary_id]
        
        # Check if refresh is needed
        if not force:
            if metadata.expires_at and datetime.now() < metadata.expires_at:
                return self.get_dictionary(dictionary_id)
        
        return self._refresh_dictionary(dictionary_id)
    
    def _refresh_dictionary(self, dictionary_id: str) -> Optional[Dict[int, bytes]]:
        """Internal dictionary refresh implementation"""
        if dictionary_id not in self.dictionary_metadata:
            return None
        
        old_metadata = self.dictionary_metadata[dictionary_id]
        
        # Mark old dictionary as deprecated
        old_metadata.status = DictionaryStatus.DEPRECATED
        self._update_dictionary_status(dictionary_id, DictionaryStatus.DEPRECATED)
        
        # Generate new dictionary with same parameters
        if old_metadata.peer_devices:
            peer_device_id = list(old_metadata.peer_devices)[0]  # Take first peer
            
            new_dict_id, new_dictionary = self.generate_shared_dictionary(
                peer_device_id=peer_device_id,
                session_id=old_metadata.session_id or f"refresh_{int(time.time())}",
                dict_type=old_metadata.dict_type,
                size=old_metadata.size
            )
            
            # Schedule old dictionary removal
            self._schedule_dictionary_removal(dictionary_id)
            
            self.metrics['dictionaries_refreshed'] += 1
            
            self.logger.info(f"Dictionary refreshed: {dictionary_id[:16]}... -> {new_dict_id[:16]}...")
            
            return new_dictionary
        
        return None
    
    def _update_usage_stats(self, dictionary_id: str):
        """Update dictionary usage statistics"""
        if dictionary_id in self.dictionary_metadata:
            metadata = self.dictionary_metadata[dictionary_id]
            metadata.usage_count += 1
            metadata.last_used = datetime.now()
            
            # Update database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE dictionaries 
                    SET usage_count = ?, last_used = ? 
                    WHERE dictionary_id = ?
                ''', (metadata.usage_count, metadata.last_used.isoformat(), dictionary_id))
                conn.commit()
    
    def _log_dictionary_usage(self, dictionary_id: str, operation: str,
                            lookup_key: Optional[str], session_id: Optional[str],
                            success: bool):
        """Log dictionary usage for audit purposes"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO dictionary_usage (dictionary_id, operation, lookup_key, timestamp, session_id, success)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (dictionary_id, operation, lookup_key, datetime.now().isoformat(), session_id, success))
            conn.commit()
    
    def _record_peer_relationship(self, dictionary_id: str, peer_device_id: str):
        """Record peer sharing relationship"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO dictionary_peers (dictionary_id, peer_device_id, shared_at, sync_version)
                VALUES (?, ?, ?, ?)
            ''', (dictionary_id, peer_device_id, datetime.now().isoformat(), 1))
            conn.commit()
    
    def synchronize_with_peer(self, peer_device_id: str, 
                            dictionary_id: Optional[str] = None) -> bool:
        """
        Synchronize dictionaries with peer device
        
        Args:
            peer_device_id: Peer device to sync with
            dictionary_id: Specific dictionary to sync (all if None)
            
        Returns:
            Success status
        """
        with self._sync_lock:
            # Prevent concurrent syncs with same peer
            sync_key = f"{peer_device_id}_{dictionary_id or 'all'}"
            if sync_key in self.pending_syncs:
                return False
            
            self.pending_syncs.add(sync_key)
            
            try:
                return self._perform_synchronization(peer_device_id, dictionary_id)
            finally:
                self.pending_syncs.discard(sync_key)
    
    def _perform_synchronization(self, peer_device_id: str, 
                               dictionary_id: Optional[str] = None) -> bool:
        """Perform actual synchronization with peer"""
        try:
            # In a full implementation, this would involve network communication
            # For now, we simulate the synchronization process
            
            sync_start = datetime.now()
            
            if dictionary_id:
                # Sync specific dictionary
                dictionaries_to_sync = [dictionary_id] if dictionary_id in self.dictionary_metadata else []
            else:
                # Sync all shared dictionaries with this peer
                dictionaries_to_sync = [
                    dict_id for dict_id, metadata in self.dictionary_metadata.items()
                    if peer_device_id in metadata.peer_devices and metadata.status == DictionaryStatus.ACTIVE
                ]
            
            success_count = 0
            
            for dict_id in dictionaries_to_sync:
                try:
                    # Mark as syncing
                    self._update_sync_status(dict_id, SyncStatus.SYNCING)
                    
                    # Simulate sync operation
                    time.sleep(0.1)  # Simulate network delay
                    
                    # Update sync status
                    self._update_sync_status(dict_id, SyncStatus.IN_SYNC)
                    self._update_peer_sync_time(dict_id, peer_device_id)
                    
                    success_count += 1
                    
                except Exception as e:
                    self.logger.error(f"Failed to sync dictionary {dict_id}: {e}")
                    self._update_sync_status(dict_id, SyncStatus.FAILED)
            
            # Log sync operation
            self._log_sync_operation(
                dictionary_id or 'all',
                peer_device_id,
                'full_sync',
                'success' if success_count > 0 else 'failed',
                sync_start,
                datetime.now(),
                None,
                success_count * 1024  # Simulated bytes transferred
            )
            
            self.metrics['sync_operations'] += 1
            if success_count == 0:
                self.metrics['failed_syncs'] += 1
            
            return success_count > 0
            
        except Exception as e:
            self.logger.error(f"Synchronization failed with {peer_device_id}: {e}")
            self.metrics['failed_syncs'] += 1
            return False
    
    def _update_sync_status(self, dictionary_id: str, status: SyncStatus):
        """Update dictionary sync status"""
        if dictionary_id in self.dictionary_metadata:
            self.dictionary_metadata[dictionary_id].sync_status = status
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'UPDATE dictionaries SET sync_status = ? WHERE dictionary_id = ?',
                    (status.value, dictionary_id)
                )
                conn.commit()
    
    def _update_peer_sync_time(self, dictionary_id: str, peer_device_id: str):
        """Update last sync time with peer"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE dictionary_peers 
                SET last_sync = ? 
                WHERE dictionary_id = ? AND peer_device_id = ?
            ''', (datetime.now().isoformat(), dictionary_id, peer_device_id))
            conn.commit()
    
    def _log_sync_operation(self, dictionary_id: str, peer_device_id: str,
                          sync_type: str, status: str,
                          started_at: datetime, completed_at: datetime,
                          error_message: Optional[str], bytes_transferred: int):
        """Log synchronization operation"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO sync_log (dictionary_id, peer_device_id, sync_type, status,
                                     started_at, completed_at, error_message, bytes_transferred)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (dictionary_id, peer_device_id, sync_type, status,
                  started_at.isoformat(), completed_at.isoformat(),
                  error_message, bytes_transferred))
            conn.commit()
    
    def list_dictionaries(self, 
                         dict_type: Optional[DictionaryType] = None,
                         status: Optional[DictionaryStatus] = None,
                         session_id: Optional[str] = None) -> List[DictionaryMetadata]:
        """
        List dictionaries matching criteria
        
        Args:
            dict_type: Filter by dictionary type
            status: Filter by status
            session_id: Filter by session ID
            
        Returns:
            List of dictionary metadata
        """
        results = []
        
        for metadata in self.dictionary_metadata.values():
            if dict_type and metadata.dict_type != dict_type:
                continue
            if status and metadata.status != status:
                continue
            if session_id and metadata.session_id != session_id:
                continue
            
            results.append(metadata)
        
        return sorted(results, key=lambda x: x.created_at, reverse=True)
    
    def cleanup_expired_dictionaries(self) -> int:
        """
        Clean up expired and deprecated dictionaries
        
        Returns:
            Number of dictionaries cleaned up
        """
        with self._lock:
            current_time = datetime.now()
            cleaned_count = 0
            
            dictionaries_to_remove = []
            
            for dict_id, metadata in list(self.dictionary_metadata.items()):
                # Mark expired dictionaries
                if (metadata.expires_at and current_time > metadata.expires_at and
                    metadata.status == DictionaryStatus.ACTIVE):
                    self._mark_dictionary_expired(dict_id)
                
                # Remove old deprecated/expired dictionaries
                if metadata.status in [DictionaryStatus.DEPRECATED, DictionaryStatus.EXPIRED, DictionaryStatus.REVOKED]:
                    # Keep for audit period (7 days for dictionaries)
                    audit_period = timedelta(days=7)
                    if current_time - metadata.created_at > audit_period:
                        dictionaries_to_remove.append(dict_id)
                        cleaned_count += 1
            
            # Remove old dictionaries
            if dictionaries_to_remove:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.executemany(
                        'DELETE FROM dictionaries WHERE dictionary_id = ?',
                        [(dict_id,) for dict_id in dictionaries_to_remove]
                    )
                    cursor.executemany(
                        'DELETE FROM dictionary_peers WHERE dictionary_id = ?',
                        [(dict_id,) for dict_id in dictionaries_to_remove]
                    )
                    conn.commit()
                
                # Remove from memory
                for dict_id in dictionaries_to_remove:
                    if dict_id in self.dictionary_metadata:
                        del self.dictionary_metadata[dict_id]
                    if dict_id in self.dictionary_cache:
                        del self.dictionary_cache[dict_id]
            
            if cleaned_count > 0:
                self.logger.info(f"Cleaned up {cleaned_count} expired dictionaries")
            
            return cleaned_count
    
    def _mark_dictionary_expired(self, dictionary_id: str):
        """Mark dictionary as expired"""
        self._update_dictionary_status(dictionary_id, DictionaryStatus.EXPIRED)
        
        # Remove from cache
        if dictionary_id in self.dictionary_cache:
            del self.dictionary_cache[dictionary_id]
        
        self.logger.warning(f"Dictionary {dictionary_id[:16]}... marked as expired")
    
    def _update_dictionary_status(self, dictionary_id: str, status: DictionaryStatus):
        """Update dictionary status"""
        if dictionary_id in self.dictionary_metadata:
            self.dictionary_metadata[dictionary_id].status = status
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE dictionaries SET status = ? WHERE dictionary_id = ?',
                (status.value, dictionary_id)
            )
            conn.commit()
    
    def _schedule_dictionary_removal(self, dictionary_id: str, delay_seconds: int = 3600):
        """Schedule dictionary removal after deprecation"""
        def remove_dictionary():
            try:
                self._update_dictionary_status(dictionary_id, DictionaryStatus.REVOKED)
                self.logger.info(f"Dictionary {dictionary_id[:16]}... removed after deprecation")
            except Exception as e:
                self.logger.error(f"Error removing dictionary {dictionary_id}: {e}")
        
        threading.Timer(delay_seconds, remove_dictionary).start()
    
    def _evict_oldest_cache_entry(self):
        """Evict oldest cache entry to make room"""
        if not self.dictionary_cache:
            return
        
        oldest_dict_id = min(self.dictionary_cache.keys(),
                           key=lambda x: self.dictionary_cache[x]['cached_at'])
        
        del self.dictionary_cache[oldest_dict_id]
        self.logger.debug(f"Evicted dictionary {oldest_dict_id[:16]}... from cache")
    
    def _start_refresh_service(self):
        """Start background dictionary refresh service"""
        def refresh_worker():
            while self.auto_refresh:
                try:
                    # Check for dictionaries needing refresh
                    current_time = datetime.now()
                    
                    for dict_id, metadata in list(self.dictionary_metadata.items()):
                        if (metadata.expires_at and 
                            current_time >= metadata.expires_at - timedelta(minutes=5) and  # 5 min buffer
                            metadata.status == DictionaryStatus.ACTIVE):
                            
                            # Submit refresh task
                            future = self.refresh_executor.submit(self._refresh_dictionary, dict_id)
                    
                    # Cleanup expired dictionaries
                    self.cleanup_expired_dictionaries()
                    
                    time.sleep(60)  # Check every minute
                    
                except Exception as e:
                    self.logger.error(f"Refresh service error: {e}")
                    time.sleep(60)
        
        refresh_thread = threading.Thread(target=refresh_worker, daemon=True)
        refresh_thread.start()
        self.logger.info("Dictionary refresh service started")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get dictionary management metrics"""
        with self._lock:
            total_dictionaries = len(self.dictionary_metadata)
            active_dictionaries = sum(1 for m in self.dictionary_metadata.values()
                                    if m.status == DictionaryStatus.ACTIVE)
            
            # Calculate cache statistics
            total_requests = self.metrics['cache_hits'] + self.metrics['cache_misses']
            cache_hit_rate = (self.metrics['cache_hits'] / total_requests) if total_requests > 0 else 0
            
            return {
                **self.metrics,
                'total_dictionaries': total_dictionaries,
                'active_dictionaries': active_dictionaries,
                'cached_dictionaries': len(self.dictionary_cache),
                'cache_hit_rate': cache_hit_rate,
                'pending_syncs': len(self.pending_syncs),
                'security_level': self.security_level,
                'auto_refresh_enabled': self.auto_refresh
            }
    
    def shutdown(self):
        """Shutdown dictionary manager and clean up resources"""
        self.logger.info("Shutting down Dictionary Manager...")
        
        # Stop refresh service
        self.auto_refresh = False
        
        # Shutdown thread pools
        if hasattr(self, 'refresh_executor'):
            self.refresh_executor.shutdown(wait=True)
        if hasattr(self, 'sync_executor'):
            self.sync_executor.shutdown(wait=True)
        
        # Clear sensitive data from memory
        self.dictionary_cache.clear()
        
        # Zero out manufacturer key
        if self.manufacturer_key:
            self.manufacturer_key = b'\x00' * len(self.manufacturer_key)
        
        self.logger.info("Dictionary Manager shutdown completed")
    
    def __del__(self):
        """Destructor to ensure cleanup"""
        try:
            self.shutdown()
        except:
            pass
    
    def __repr__(self) -> str:
        """String representation"""
        return (f"DynamicDictionaryManager(device_id='{self.device_id[:16]}...', "
                f"security_level='{self.security_level}', "
                f"dictionaries={len(self.dictionary_metadata)}, "
                f"auto_refresh={self.auto_refresh})")
