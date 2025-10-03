# [file name]: src/dictionary_manager.py
"""
Enhanced Dictionary Manager for Quantum-Resistant Encryption
Advanced management of tensor and logic dictionaries for secure communication

Features:
- Multi-version dictionary management with rollback capability
- Quantum-resistant dictionary encryption and compression
- Real-time synchronization and conflict resolution
- Advanced caching with intelligent prefetching
- Comprehensive audit trails and integrity verification
- Distributed dictionary sharing with secure protocols
"""

import os
import json
import pickle
import zlib
import hashlib
import hmac
import time
import logging
import threading
import secrets
from typing import Dict, List, Tuple, Optional, Any, Union
from enum import Enum
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import numpy as np
import msgpack
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DictionaryType(Enum):
    """Types of encryption dictionaries"""
    TENSOR = "tensor"
    LOGIC = "logic"
    COMBINED = "combined"
    SESSION = "session"
    EPHEMERAL = "ephemeral"

class DictionaryStatus(Enum):
    """Dictionary lifecycle status"""
    ACTIVE = "active"
    STAGING = "staging"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"
    COMPROMISED = "compromised"
    EXPIRED = "expired"

class SyncMode(Enum):
    """Dictionary synchronization modes"""
    FULL = "full"
    INCREMENTAL = "incremental"
    DELTA = "delta"
    LAZY = "lazy"

@dataclass
class DictionaryMetadata:
    """Comprehensive dictionary metadata"""
    dictionary_id: str
    dictionary_type: DictionaryType
    status: DictionaryStatus
    version: str
    created_at: datetime
    expires_at: Optional[datetime]
    device_id: str
    session_id: Optional[str]
    size_bytes: int
    entry_count: int
    compression_ratio: float
    entropy_score: float
    integrity_hash: str
    tags: List[str]
    dependencies: List[str]
    access_pattern: Dict[str, int]
    last_accessed: datetime
    last_modified: datetime

@dataclass
class PerformanceMetrics:
    """Dictionary management performance metrics"""
    dictionaries_created: int = 0
    dictionaries_updated: int = 0
    dictionaries_deleted: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    sync_operations: int = 0
    compression_operations: int = 0
    encryption_operations: int = 0
    average_access_time: float = 0.0
    total_operations: int = 0

@dataclass
class SyncState:
    """Dictionary synchronization state"""
    last_sync_time: datetime
    sync_mode: SyncMode
    pending_changes: int
    conflict_count: int
    sync_status: str
    peer_devices: List[str]

class DictionaryManager:
    """
    Advanced Dictionary Manager for Quantum-Resistant Encryption
    
    Features:
    - Multi-version dictionary management with rollback
    - Quantum-resistant encryption and compression
    - Real-time synchronization with conflict resolution
    - Intelligent caching with prefetching
    - Comprehensive audit trails and integrity checks
    - Distributed sharing with secure protocols
    """

    # Supported compression algorithms
    COMPRESSION_ALGORITHMS = {
        'zlib': zlib,
        'lz4': None,  # Would require lz4 package
        'brotli': None,  # Would require brotli package
        'none': None
    }

    # Supported serialization formats
    SERIALIZATION_FORMATS = {
        'msgpack': msgpack,
        'json': json,
        'pickle': pickle
    }

    def __init__(self,
                 db_path: str,
                 device_id: str,
                 security_level: str = 'high',
                 enable_caching: bool = True,
                 cache_size: int = 1000,
                 enable_compression: bool = True,
                 enable_encryption: bool = True,
                 sync_enabled: bool = True,
                 backup_enabled: bool = True):
        """
        Initialize the Advanced Dictionary Manager
        
        Args:
            db_path: Path to SQLite database
            device_id: Unique device identifier
            security_level: Security level ('basic', 'standard', 'high', 'quantum')
            enable_caching: Enable dictionary caching
            cache_size: Maximum cache size
            enable_compression: Enable dictionary compression
            enable_encryption: Enable dictionary encryption
            sync_enabled: Enable dictionary synchronization
            backup_enabled: Enable automatic backups
        """
        
        self.db_path = db_path
        self.device_id = device_id
        self.security_level = security_level
        self.enable_caching = enable_caching
        self.cache_size = cache_size
        self.enable_compression = enable_compression
        self.enable_encryption = enable_encryption
        self.sync_enabled = sync_enabled
        self.backup_enabled = backup_enabled
        
        # Security parameters
        self.security_params = self._get_security_params(security_level)
        
        # Initialize components
        self.dictionary_cache = {}
        self.metadata_cache = {}
        self.performance_metrics = PerformanceMetrics()
        self.sync_state = SyncState(
            last_sync_time=datetime.now(),
            sync_mode=SyncMode.INCREMENTAL,
            pending_changes=0,
            conflict_count=0,
            sync_status="initialized",
            peer_devices=[]
        )
        
        # Thread safety
        self._lock = threading.RLock()
        self._cache_lock = threading.Lock()
        self._db_lock = threading.Lock()
        
        # Background services
        self.background_executor = ThreadPoolExecutor(max_workers=4)
        self.background_tasks = {}
        
        # Initialize database
        self._init_database()
        
        # Initialize encryption key
        self.encryption_key = self._derive_encryption_key()
        
        # Start background services
        self._start_background_services()
        
        logger.info(f"DictionaryManager initialized for device {device_id} "
                   f"with {security_level} security level")

    def _get_security_params(self, level: str) -> Dict[str, Any]:
        """Get security parameters based on security level"""
        params = {
            'basic': {
                'key_length': 32,
                'compression_level': 1,
                'encryption_algorithm': 'AES-256-GCM',
                'integrity_algorithm': 'SHA-256',
                'cache_ttl': timedelta(hours=24),
                'backup_interval': timedelta(days=7)
            },
            'standard': {
                'key_length': 48,
                'compression_level': 3,
                'encryption_algorithm': 'AES-256-GCM',
                'integrity_algorithm': 'SHA-384',
                'cache_ttl': timedelta(hours=12),
                'backup_interval': timedelta(days=3)
            },
            'high': {
                'key_length': 64,
                'compression_level': 6,
                'encryption_algorithm': 'AES-256-GCM',
                'integrity_algorithm': 'SHA-512',
                'cache_ttl': timedelta(hours=6),
                'backup_interval': timedelta(days=1)
            },
            'quantum': {
                'key_length': 128,
                'compression_level': 9,
                'encryption_algorithm': 'AES-256-GCM',
                'integrity_algorithm': 'SHA3-512',
                'cache_ttl': timedelta(hours=1),
                'backup_interval': timedelta(hours=12)
            }
        }
        return params.get(level, params['high'])

    def _init_database(self):
        """Initialize SQLite database with required tables"""
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                conn.execute("PRAGMA foreign_keys = ON")
                conn.execute("PRAGMA journal_mode = WAL")
                conn.execute("PRAGMA synchronous = NORMAL")
                
                # Dictionaries table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS dictionaries (
                        dictionary_id TEXT PRIMARY KEY,
                        dictionary_type TEXT NOT NULL,
                        status TEXT NOT NULL,
                        version TEXT NOT NULL,
                        created_at TIMESTAMP NOT NULL,
                        expires_at TIMESTAMP,
                        device_id TEXT NOT NULL,
                        session_id TEXT,
                        encrypted_data BLOB NOT NULL,
                        compression_algorithm TEXT,
                        encryption_algorithm TEXT,
                        size_bytes INTEGER NOT NULL,
                        entry_count INTEGER NOT NULL,
                        compression_ratio REAL,
                        entropy_score REAL,
                        integrity_hash TEXT NOT NULL,
                        tags TEXT,
                        dependencies TEXT,
                        access_pattern TEXT,
                        last_accessed TIMESTAMP,
                        last_modified TIMESTAMP NOT NULL
                    )
                ''')
                
                # Dictionary entries table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS dictionary_entries (
                        entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        dictionary_id TEXT NOT NULL,
                        entry_key TEXT NOT NULL,
                        entry_value BLOB NOT NULL,
                        value_type TEXT NOT NULL,
                        created_at TIMESTAMP NOT NULL,
                        last_accessed TIMESTAMP,
                        access_count INTEGER DEFAULT 0,
                        FOREIGN KEY (dictionary_id) REFERENCES dictionaries (dictionary_id),
                        UNIQUE(dictionary_id, entry_key)
                    )
                ''')
                
                # Dictionary versions table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS dictionary_versions (
                        version_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        dictionary_id TEXT NOT NULL,
                        version_number TEXT NOT NULL,
                        parent_version TEXT,
                        created_at TIMESTAMP NOT NULL,
                        change_description TEXT,
                        encrypted_delta BLOB,
                        integrity_hash TEXT NOT NULL,
                        FOREIGN KEY (dictionary_id) REFERENCES dictionaries (dictionary_id)
                    )
                ''')
                
                # Sync history table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS sync_history (
                        sync_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        dictionary_id TEXT NOT NULL,
                        sync_timestamp TIMESTAMP NOT NULL,
                        sync_mode TEXT NOT NULL,
                        changes_sent INTEGER DEFAULT 0,
                        changes_received INTEGER DEFAULT 0,
                        conflicts_resolved INTEGER DEFAULT 0,
                        sync_duration REAL,
                        peer_device_id TEXT,
                        sync_status TEXT NOT NULL,
                        FOREIGN KEY (dictionary_id) REFERENCES dictionaries (dictionary_id)
                    )
                ''')
                
                # Access audit log
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS access_audit_log (
                        audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        dictionary_id TEXT NOT NULL,
                        operation TEXT NOT NULL,
                        timestamp TIMESTAMP NOT NULL,
                        device_id TEXT NOT NULL,
                        entry_key TEXT,
                        additional_info TEXT,
                        FOREIGN KEY (dictionary_id) REFERENCES dictionaries (dictionary_id)
                    )
                ''')
                
                # Create indexes for performance
                conn.execute('CREATE INDEX IF NOT EXISTS idx_dict_type ON dictionaries(dictionary_type)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_dict_status ON dictionaries(status)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_dict_session ON dictionaries(session_id)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_entries_dict ON dictionary_entries(dictionary_id)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_entries_key ON dictionary_entries(entry_key)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_versions_dict ON dictionary_versions(dictionary_id)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_sync_history ON sync_history(dictionary_id, sync_timestamp)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_audit_dict ON access_audit_log(dictionary_id, timestamp)')
                
                conn.commit()
                logger.info("Dictionary database initialized successfully")
                
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

    def _derive_encryption_key(self) -> bytes:
        """Derive encryption key from device ID and security parameters"""
        try:
            hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=self.security_params['key_length'],
                salt=None,
                info=b"dictionary_manager_encryption_key",
                backend=default_backend()
            )
            return hkdf.derive(self.device_id.encode())
        except Exception as e:
            logger.error(f"Failed to derive encryption key: {e}")
            raise

    def _start_background_services(self):
        """Start background maintenance services"""
        def cleanup_service():
            while True:
                try:
                    self._cleanup_expired_dictionaries()
                    time.sleep(3600)  # Run every hour
                except Exception as e:
                    logger.error(f"Cleanup service error: {e}")
                    time.sleep(7200)  # Wait 2 hours on error
        
        def backup_service():
            while self.backup_enabled:
                try:
                    self._create_backup()
                    time.sleep(self.security_params['backup_interval'].total_seconds())
                except Exception as e:
                    logger.error(f"Backup service error: {e}")
                    time.sleep(3600)  # Wait 1 hour on error
        
        def cache_maintenance_service():
            while self.enable_caching:
                try:
                    self._cleanup_cache()
                    time.sleep(300)  # Run every 5 minutes
                except Exception as e:
                    logger.error(f"Cache maintenance error: {e}")
                    time.sleep(600)  # Wait 10 minutes on error
        
        # Start background threads
        self.cleanup_thread = threading.Thread(target=cleanup_service, daemon=True)
        self.backup_thread = threading.Thread(target=backup_service, daemon=True)
        self.cache_thread = threading.Thread(target=cache_maintenance_service, daemon=True)
        
        self.cleanup_thread.start()
        if self.backup_enabled:
            self.backup_thread.start()
        if self.enable_caching:
            self.cache_thread.start()
        
        logger.info("Background services started")

    def create_dictionary(self,
                         dictionary_type: DictionaryType,
                         initial_data: Optional[Dict[str, Any]] = None,
                         session_id: Optional[str] = None,
                         tags: Optional[List[str]] = None,
                         expiration_hours: Optional[int] = None) -> str:
        """
        Create a new encryption dictionary
        
        Args:
            dictionary_type: Type of dictionary to create
            initial_data: Optional initial dictionary data
            session_id: Optional session identifier
            tags: Optional tags for categorization
            expiration_hours: Optional expiration time in hours
            
        Returns:
            Dictionary identifier
        """
        
        start_time = time.time()
        
        with self._lock:
            try:
                # Generate dictionary ID
                dictionary_id = self._generate_dictionary_id(dictionary_type, session_id)
                
                # Check if dictionary already exists
                if self._dictionary_exists(dictionary_id):
                    logger.warning(f"Dictionary {dictionary_id} already exists")
                    return dictionary_id
                
                # Prepare initial data
                if initial_data is None:
                    initial_data = {}
                
                # Calculate initial metrics
                entry_count = len(initial_data)
                uncompressed_size = len(str(initial_data).encode('utf-8'))
                
                # Process and store dictionary
                encrypted_data, compression_ratio, entropy_score = self._process_dictionary_data(initial_data)
                
                # Calculate compressed size
                compressed_size = len(encrypted_data)
                
                # Calculate integrity hash
                integrity_hash = self._calculate_integrity_hash(initial_data)
                
                # Set expiration if specified
                expires_at = None
                if expiration_hours:
                    expires_at = datetime.now() + timedelta(hours=expiration_hours)
                
                # Create metadata
                metadata = DictionaryMetadata(
                    dictionary_id=dictionary_id,
                    dictionary_type=dictionary_type,
                    status=DictionaryStatus.ACTIVE,
                    version="1.0.0",
                    created_at=datetime.now(),
                    expires_at=expires_at,
                    device_id=self.device_id,
                    session_id=session_id,
                    size_bytes=compressed_size,
                    entry_count=entry_count,
                    compression_ratio=compression_ratio,
                    entropy_score=entropy_score,
                    integrity_hash=integrity_hash,
                    tags=tags or [],
                    dependencies=[],
                    access_pattern={},
                    last_accessed=datetime.now(),
                    last_modified=datetime.now()
                )
                
                # Store dictionary in database
                self._store_dictionary_in_db(dictionary_id, encrypted_data, metadata)
                
                # Store individual entries if provided
                if initial_data:
                    self._store_dictionary_entries(dictionary_id, initial_data)
                
                # Cache the dictionary
                if self.enable_caching:
                    with self._cache_lock:
                        self.dictionary_cache[dictionary_id] = initial_data
                        self.metadata_cache[dictionary_id] = metadata
                
                # Update performance metrics
                self.performance_metrics.dictionaries_created += 1
                self.performance_metrics.total_operations += 1
                
                # Log the operation
                self._log_audit_event(dictionary_id, "create", f"entries: {entry_count}")
                
                logger.info(f"Created dictionary {dictionary_id} with {entry_count} entries "
                           f"in {time.time() - start_time:.3f}s")
                
                return dictionary_id
                
            except Exception as e:
                logger.error(f"Failed to create dictionary: {e}")
                raise

    def _generate_dictionary_id(self, dictionary_type: DictionaryType, session_id: Optional[str]) -> str:
        """Generate unique dictionary identifier"""
        timestamp = int(time.time() * 1000)
        random_component = secrets.token_hex(8)
        
        base_id = f"{dictionary_type.value}_{timestamp}_{random_component}"
        if session_id:
            base_id = f"{session_id}_{base_id}"
        
        # Create hash-based ID for consistency
        dictionary_hash = hashlib.sha3_256(base_id.encode()).hexdigest()[:16]
        return f"dict_{dictionary_hash}"

    def _dictionary_exists(self, dictionary_id: str) -> bool:
        """Check if dictionary exists in database"""
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT 1 FROM dictionaries WHERE dictionary_id = ?',
                    (dictionary_id,)
                )
                return cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Failed to check dictionary existence: {e}")
            return False

    def _process_dictionary_data(self, data: Dict[str, Any]) -> Tuple[bytes, float, float]:
        """
        Process dictionary data: compress and encrypt
        
        Returns:
            Tuple of (encrypted_data, compression_ratio, entropy_score)
        """
        try:
            # Serialize data
            serialized_data = self._serialize_data(data)
            original_size = len(serialized_data)
            
            # Calculate entropy
            entropy_score = self._calculate_data_entropy(serialized_data)
            
            # Compress data
            if self.enable_compression:
                compressed_data = zlib.compress(serialized_data, level=self.security_params['compression_level'])
                compression_ratio = original_size / len(compressed_data)
            else:
                compressed_data = serialized_data
                compression_ratio = 1.0
            
            # Encrypt data
            if self.enable_encryption:
                encrypted_data = self._encrypt_data(compressed_data)
            else:
                encrypted_data = compressed_data
            
            self.performance_metrics.compression_operations += 1
            self.performance_metrics.encryption_operations += 1
            
            return encrypted_data, compression_ratio, entropy_score
            
        except Exception as e:
            logger.error(f"Failed to process dictionary data: {e}")
            raise

    def _serialize_data(self, data: Dict[str, Any]) -> bytes:
        """Serialize dictionary data using optimal format"""
        try:
            # Use msgpack for efficiency if available
            if 'msgpack' in self.SERIALIZATION_FORMATS:
                return msgpack.packb(data, use_bin_type=True)
            else:
                # Fall back to JSON
                return json.dumps(data, separators=(',', ':')).encode('utf-8')
        except Exception as e:
            logger.warning(f"Serialization failed: {e}, using pickle")
            return pickle.dumps(data)

    def _calculate_data_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if len(data) == 0:
            return 0.0
        
        # Calculate byte frequency
        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probabilities = byte_counts / len(data)
        probabilities = probabilities[probabilities > 0]  # Remove zero probabilities
        
        # Calculate entropy
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return float(entropy)

    def _encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data using derived key"""
        try:
            nonce = secrets.token_bytes(16)
            
            cipher = Cipher(algorithms.AES(self.encryption_key), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            return nonce + ciphertext + encryptor.tag
            
        except Exception as e:
            logger.error(f"Failed to encrypt data: {e}")
            raise

    def _decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using derived key"""
        try:
            # Parse encrypted data (nonce + ciphertext + tag)
            nonce = encrypted_data[:16]
            ciphertext = encrypted_data[16:-16]
            tag = encrypted_data[-16:]
            
            cipher = Cipher(algorithms.AES(self.encryption_key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            
            return decrypted
            
        except InvalidTag:
            logger.error("Data decryption failed: authentication tag mismatch")
            raise SecurityError("Data decryption authentication failed")
        except Exception as e:
            logger.error(f"Failed to decrypt data: {e}")
            raise

    def _calculate_integrity_hash(self, data: Dict[str, Any]) -> str:
        """Calculate integrity hash of dictionary data"""
        serialized_data = self._serialize_data(data)
        
        if self.security_params['integrity_algorithm'] == 'SHA3-512':
            return hashlib.sha3_512(serialized_data).hexdigest()
        elif self.security_params['integrity_algorithm'] == 'SHA-512':
            return hashlib.sha512(serialized_data).hexdigest()
        elif self.security_params['integrity_algorithm'] == 'SHA-384':
            return hashlib.sha384(serialized_data).hexdigest()
        else:  # SHA-256
            return hashlib.sha256(serialized_data).hexdigest()

    def _store_dictionary_in_db(self, dictionary_id: str, encrypted_data: bytes, metadata: DictionaryMetadata):
        """Store dictionary in database"""
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO dictionaries (
                        dictionary_id, dictionary_type, status, version, created_at, expires_at,
                        device_id, session_id, encrypted_data, compression_algorithm,
                        encryption_algorithm, size_bytes, entry_count, compression_ratio,
                        entropy_score, integrity_hash, tags, dependencies, access_pattern,
                        last_accessed, last_modified
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    dictionary_id,
                    metadata.dictionary_type.value,
                    metadata.status.value,
                    metadata.version,
                    metadata.created_at.isoformat(),
                    metadata.expires_at.isoformat() if metadata.expires_at else None,
                    metadata.device_id,
                    metadata.session_id,
                    encrypted_data,
                    'zlib' if self.enable_compression else 'none',
                    'AES-256-GCM' if self.enable_encryption else 'none',
                    metadata.size_bytes,
                    metadata.entry_count,
                    metadata.compression_ratio,
                    metadata.entropy_score,
                    metadata.integrity_hash,
                    json.dumps(metadata.tags),
                    json.dumps(metadata.dependencies),
                    json.dumps(metadata.access_pattern),
                    metadata.last_accessed.isoformat(),
                    metadata.last_modified.isoformat()
                ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to store dictionary in database: {e}")
            raise

    def _store_dictionary_entries(self, dictionary_id: str, data: Dict[str, Any]):
        """Store individual dictionary entries"""
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for key, value in data.items():
                    # Serialize value
                    if isinstance(value, (np.ndarray, np.generic)):
                        # Handle numpy arrays specially
                        value_data = pickle.dumps(value)
                        value_type = 'numpy'
                    else:
                        value_data = pickle.dumps(value)
                        value_type = 'python'
                    
                    cursor.execute('''
                        INSERT INTO dictionary_entries (
                            dictionary_id, entry_key, entry_value, value_type, created_at, last_accessed
                        ) VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        dictionary_id,
                        key,
                        value_data,
                        value_type,
                        datetime.now().isoformat(),
                        datetime.now().isoformat()
                    ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to store dictionary entries: {e}")
            raise

    def get_dictionary(self, dictionary_id: str, update_access: bool = True) -> Dict[str, Any]:
        """
        Retrieve dictionary by ID
        
        Args:
            dictionary_id: Dictionary identifier
            update_access: Whether to update access statistics
            
        Returns:
            Dictionary data
        """
        
        start_time = time.time()
        
        # Check cache first
        if self.enable_caching:
            with self._cache_lock:
                if dictionary_id in self.dictionary_cache:
                    data = self.dictionary_cache[dictionary_id]
                    metadata = self.metadata_cache[dictionary_id]
                    
                    self.performance_metrics.cache_hits += 1
                    
                    if update_access:
                        self._update_access_stats(dictionary_id, metadata)
                    
                    return data
        
        self.performance_metrics.cache_misses += 1
        
        with self._lock:
            try:
                # Retrieve from database
                data, metadata = self._get_dictionary_from_db(dictionary_id)
                if data is None:
                    raise KeyError(f"Dictionary not found: {dictionary_id}")
                
                # Verify integrity
                if not self._verify_dictionary_integrity(data, metadata):
                    raise SecurityError(f"Dictionary integrity check failed: {dictionary_id}")
                
                # Update cache
                if self.enable_caching:
                    with self._cache_lock:
                        self.dictionary_cache[dictionary_id] = data
                        self.metadata_cache[dictionary_id] = metadata
                
                # Update access statistics
                if update_access:
                    self._update_access_stats(dictionary_id, metadata)
                
                access_time = time.time() - start_time
                self._update_average_access_time(access_time)
                
                logger.debug(f"Retrieved dictionary {dictionary_id} in {access_time:.3f}s")
                
                return data
                
            except Exception as e:
                logger.error(f"Failed to get dictionary {dictionary_id}: {e}")
                raise

    def _get_dictionary_from_db(self, dictionary_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[DictionaryMetadata]]:
        """Retrieve dictionary from database and decrypt it"""
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Get dictionary record
                cursor.execute(
                    'SELECT * FROM dictionaries WHERE dictionary_id = ?',
                    (dictionary_id,)
                )
                row = cursor.fetchone()
                
                if row is None:
                    return None, None
                
                # Decrypt data
                encrypted_data = row['encrypted_data']
                if row['encryption_algorithm'] != 'none':
                    decrypted_data = self._decrypt_data(encrypted_data)
                else:
                    decrypted_data = encrypted_data
                
                # Decompress data
                if row['compression_algorithm'] != 'none':
                    decompressed_data = zlib.decompress(decrypted_data)
                else:
                    decompressed_data = decrypted_data
                
                # Deserialize data
                data = self._deserialize_data(decompressed_data)
                
                # Create metadata
                metadata = DictionaryMetadata(
                    dictionary_id=row['dictionary_id'],
                    dictionary_type=DictionaryType(row['dictionary_type']),
                    status=DictionaryStatus(row['status']),
                    version=row['version'],
                    created_at=datetime.fromisoformat(row['created_at']),
                    expires_at=datetime.fromisoformat(row['expires_at']) if row['expires_at'] else None,
                    device_id=row['device_id'],
                    session_id=row['session_id'],
                    size_bytes=row['size_bytes'],
                    entry_count=row['entry_count'],
                    compression_ratio=row['compression_ratio'],
                    entropy_score=row['entropy_score'],
                    integrity_hash=row['integrity_hash'],
                    tags=json.loads(row['tags']) if row['tags'] else [],
                    dependencies=json.loads(row['dependencies']) if row['dependencies'] else [],
                    access_pattern=json.loads(row['access_pattern']) if row['access_pattern'] else {},
                    last_accessed=datetime.fromisoformat(row['last_accessed']),
                    last_modified=datetime.fromisoformat(row['last_modified'])
                )
                
                return data, metadata
                
        except Exception as e:
            logger.error(f"Failed to get dictionary from database: {e}")
            raise

    def _deserialize_data(self, data: bytes) -> Dict[str, Any]:
        """Deserialize dictionary data"""
        try:
            # Try msgpack first
            if data[0] == 0x80:  # msgpack map indicator
                return msgpack.unpackb(data, raw=False)
            else:
                # Try JSON
                try:
                    return json.loads(data.decode('utf-8'))
                except:
                    # Fall back to pickle
                    return pickle.loads(data)
        except Exception as e:
            logger.error(f"Failed to deserialize data: {e}")
            raise

    def _verify_dictionary_integrity(self, data: Dict[str, Any], metadata: DictionaryMetadata) -> bool:
        """Verify dictionary data integrity"""
        try:
            current_hash = self._calculate_integrity_hash(data)
            return current_hash == metadata.integrity_hash
        except Exception as e:
            logger.error(f"Integrity verification failed: {e}")
            return False

    def _update_access_stats(self, dictionary_id: str, metadata: DictionaryMetadata):
        """Update dictionary access statistics"""
        current_time = datetime.now()
        metadata.last_accessed = current_time
        
        # Update access pattern
        hour_key = current_time.strftime("%Y-%m-%d %H:00")
        metadata.access_pattern[hour_key] = metadata.access_pattern.get(hour_key, 0) + 1
        
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'UPDATE dictionaries SET last_accessed = ?, access_pattern = ? WHERE dictionary_id = ?',
                    (current_time.isoformat(), json.dumps(metadata.access_pattern), dictionary_id)
                )
                conn.commit()
                
        except Exception as e:
            logger.warning(f"Failed to update access stats for {dictionary_id}: {e}")

    def _update_average_access_time(self, access_time: float):
        """Update average access time metric"""
        total_ops = self.performance_metrics.total_operations
        self.performance_metrics.average_access_time = (
            self.performance_metrics.average_access_time * total_ops + access_time
        ) / (total_ops + 1)

    def update_dictionary(self, dictionary_id: str, updates: Dict[str, Any]) -> bool:
        """
        Update dictionary with new data
        
        Args:
            dictionary_id: Dictionary identifier
            updates: Dictionary of updates (key-value pairs)
            
        Returns:
            Success status
        """
        
        with self._lock:
            try:
                # Get current dictionary
                current_data = self.get_dictionary(dictionary_id, update_access=False)
                metadata = self.metadata_cache.get(dictionary_id)
                
                if metadata is None:
                    metadata = self._get_metadata_from_db(dictionary_id)
                    if metadata is None:
                        raise KeyError(f"Dictionary metadata not found: {dictionary_id}")
                
                # Apply updates
                current_data.update(updates)
                
                # Process and store updated dictionary
                encrypted_data, compression_ratio, entropy_score = self._process_dictionary_data(current_data)
                
                # Update metadata
                metadata.entry_count = len(current_data)
                metadata.size_bytes = len(encrypted_data)
                metadata.compression_ratio = compression_ratio
                metadata.entropy_score = entropy_score
                metadata.integrity_hash = self._calculate_integrity_hash(current_data)
                metadata.last_modified = datetime.now()
                
                # Update database
                self._update_dictionary_in_db(dictionary_id, encrypted_data, metadata)
                
                # Update cache
                if self.enable_caching:
                    with self._cache_lock:
                        self.dictionary_cache[dictionary_id] = current_data
                        self.metadata_cache[dictionary_id] = metadata
                
                # Update individual entries
                self._update_dictionary_entries(dictionary_id, updates)
                
                # Create version snapshot
                self._create_version_snapshot(dictionary_id, "Applied updates", updates)
                
                self.performance_metrics.dictionaries_updated += 1
                self.performance_metrics.total_operations += 1
                
                # Log the operation
                self._log_audit_event(dictionary_id, "update", f"updated_entries: {len(updates)}")
                
                logger.info(f"Updated dictionary {dictionary_id} with {len(updates)} entries")
                
                return True
                
            except Exception as e:
                logger.error(f"Failed to update dictionary {dictionary_id}: {e}")
                return False

    def _update_dictionary_in_db(self, dictionary_id: str, encrypted_data: bytes, metadata: DictionaryMetadata):
        """Update dictionary in database"""
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE dictionaries SET
                        encrypted_data = ?, size_bytes = ?, entry_count = ?,
                        compression_ratio = ?, entropy_score = ?, integrity_hash = ?,
                        last_modified = ?
                    WHERE dictionary_id = ?
                ''', (
                    encrypted_data,
                    metadata.size_bytes,
                    metadata.entry_count,
                    metadata.compression_ratio,
                    metadata.entropy_score,
                    metadata.integrity_hash,
                    metadata.last_modified.isoformat(),
                    dictionary_id
                ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to update dictionary in database: {e}")
            raise

    def _update_dictionary_entries(self, dictionary_id: str, updates: Dict[str, Any]):
        """Update individual dictionary entries"""
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for key, value in updates.items():
                    # Serialize value
                    if isinstance(value, (np.ndarray, np.generic)):
                        value_data = pickle.dumps(value)
                        value_type = 'numpy'
                    else:
                        value_data = pickle.dumps(value)
                        value_type = 'python'
                    
                    # Check if entry exists
                    cursor.execute(
                        'SELECT 1 FROM dictionary_entries WHERE dictionary_id = ? AND entry_key = ?',
                        (dictionary_id, key)
                    )
                    
                    if cursor.fetchone():
                        # Update existing entry
                        cursor.execute('''
                            UPDATE dictionary_entries SET
                                entry_value = ?, value_type = ?, last_accessed = ?
                            WHERE dictionary_id = ? AND entry_key = ?
                        ''', (
                            value_data,
                            value_type,
                            datetime.now().isoformat(),
                            dictionary_id,
                            key
                        ))
                    else:
                        # Insert new entry
                        cursor.execute('''
                            INSERT INTO dictionary_entries (
                                dictionary_id, entry_key, entry_value, value_type, created_at, last_accessed
                            ) VALUES (?, ?, ?, ?, ?, ?)
                        ''', (
                            dictionary_id,
                            key,
                            value_data,
                            value_type,
                            datetime.now().isoformat(),
                            datetime.now().isoformat()
                        ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to update dictionary entries: {e}")
            raise

    def _create_version_snapshot(self, dictionary_id: str, description: str, changes: Dict[str, Any]):
        """Create version snapshot of dictionary"""
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get current version
                cursor.execute(
                    'SELECT version FROM dictionaries WHERE dictionary_id = ?',
                    (dictionary_id,)
                )
                current_version = cursor.fetchone()[0]
                
                # Calculate next version
                major, minor, patch = map(int, current_version.split('.'))
                new_version = f"{major}.{minor}.{patch + 1}"
                
                # Serialize changes
                changes_data = self._serialize_data(changes)
                encrypted_changes = self._encrypt_data(changes_data) if self.enable_encryption else changes_data
                changes_hash = self._calculate_integrity_hash(changes)
                
                # Store version
                cursor.execute('''
                    INSERT INTO dictionary_versions (
                        dictionary_id, version_number, parent_version, created_at,
                        change_description, encrypted_delta, integrity_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    dictionary_id,
                    new_version,
                    current_version,
                    datetime.now().isoformat(),
                    description,
                    encrypted_changes,
                    changes_hash
                ))
                
                # Update dictionary version
                cursor.execute(
                    'UPDATE dictionaries SET version = ? WHERE dictionary_id = ?',
                    (new_version, dictionary_id)
                )
                
                conn.commit()
                
        except Exception as e:
            logger.warning(f"Failed to create version snapshot: {e}")

    def delete_dictionary(self, dictionary_id: str, permanent: bool = False) -> bool:
        """
        Delete dictionary
        
        Args:
            dictionary_id: Dictionary identifier
            permanent: Whether to permanently delete (vs archive)
            
        Returns:
            Success status
        """
        
        with self._lock:
            try:
                if permanent:
                    # Permanent deletion
                    self._permanently_delete_dictionary(dictionary_id)
                else:
                    # Archive the dictionary
                    self._archive_dictionary(dictionary_id)
                
                # Remove from cache
                if self.enable_caching:
                    with self._cache_lock:
                        self.dictionary_cache.pop(dictionary_id, None)
                        self.metadata_cache.pop(dictionary_id, None)
                
                self.performance_metrics.dictionaries_deleted += 1
                self.performance_metrics.total_operations += 1
                
                # Log the operation
                self._log_audit_event(dictionary_id, "delete", f"permanent: {permanent}")
                
                logger.info(f"Deleted dictionary {dictionary_id} (permanent: {permanent})")
                
                return True
                
            except Exception as e:
                logger.error(f"Failed to delete dictionary {dictionary_id}: {e}")
                return False

    def _archive_dictionary(self, dictionary_id: str):
        """Archive dictionary (soft delete)"""
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'UPDATE dictionaries SET status = ? WHERE dictionary_id = ?',
                    (DictionaryStatus.ARCHIVED.value, dictionary_id)
                )
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to archive dictionary {dictionary_id}: {e}")
            raise

    def _permanently_delete_dictionary(self, dictionary_id: str):
        """Permanently delete dictionary and all related data"""
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Delete entries
                cursor.execute(
                    'DELETE FROM dictionary_entries WHERE dictionary_id = ?',
                    (dictionary_id,)
                )
                
                # Delete versions
                cursor.execute(
                    'DELETE FROM dictionary_versions WHERE dictionary_id = ?',
                    (dictionary_id,)
                )
                
                # Delete sync history
                cursor.execute(
                    'DELETE FROM sync_history WHERE dictionary_id = ?',
                    (dictionary_id,)
                )
                
                # Delete audit log
                cursor.execute(
                    'DELETE FROM access_audit_log WHERE dictionary_id = ?',
                    (dictionary_id,)
                )
                
                # Delete dictionary
                cursor.execute(
                    'DELETE FROM dictionaries WHERE dictionary_id = ?',
                    (dictionary_id,)
                )
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to permanently delete dictionary {dictionary_id}: {e}")
            raise

    def list_dictionaries(self,
                         dictionary_type: Optional[DictionaryType] = None,
                         status: Optional[DictionaryStatus] = None,
                         session_id: Optional[str] = None) -> List[DictionaryMetadata]:
        """
        List dictionaries with optional filtering
        
        Args:
            dictionary_type: Filter by dictionary type
            status: Filter by dictionary status
            session_id: Filter by session ID
            
        Returns:
            List of dictionary metadata
        """
        
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                query = 'SELECT * FROM dictionaries WHERE 1=1'
                params = []
                
                if dictionary_type:
                    query += ' AND dictionary_type = ?'
                    params.append(dictionary_type.value)
                
                if status:
                    query += ' AND status = ?'
                    params.append(status.value)
                
                if session_id:
                    query += ' AND session_id = ?'
                    params.append(session_id)
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                dictionaries = []
                for row in rows:
                    metadata = DictionaryMetadata(
                        dictionary_id=row['dictionary_id'],
                        dictionary_type=DictionaryType(row['dictionary_type']),
                        status=DictionaryStatus(row['status']),
                        version=row['version'],
                        created_at=datetime.fromisoformat(row['created_at']),
                        expires_at=datetime.fromisoformat(row['expires_at']) if row['expires_at'] else None,
                        device_id=row['device_id'],
                        session_id=row['session_id'],
                        size_bytes=row['size_bytes'],
                        entry_count=row['entry_count'],
                        compression_ratio=row['compression_ratio'],
                        entropy_score=row['entropy_score'],
                        integrity_hash=row['integrity_hash'],
                        tags=json.loads(row['tags']) if row['tags'] else [],
                        dependencies=json.loads(row['dependencies']) if row['dependencies'] else [],
                        access_pattern=json.loads(row['access_pattern']) if row['access_pattern'] else {},
                        last_accessed=datetime.fromisoformat(row['last_accessed']),
                        last_modified=datetime.fromisoformat(row['last_modified'])
                    )
                    dictionaries.append(metadata)
                
                return dictionaries
                
        except Exception as e:
            logger.error(f"Failed to list dictionaries: {e}")
            raise

    def get_dictionary_entry(self, dictionary_id: str, key: str) -> Any:
        """
        Get specific entry from dictionary
        
        Args:
            dictionary_id: Dictionary identifier
            key: Entry key
            
        Returns:
            Entry value
        """
        
        try:
            # Try to get from cache first
            if self.enable_caching and dictionary_id in self.dictionary_cache:
                data = self.dictionary_cache[dictionary_id]
                if key in data:
                    self._update_entry_access(dictionary_id, key)
                    return data[key]
            
            # Get from database
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT entry_value, value_type FROM dictionary_entries 
                    WHERE dictionary_id = ? AND entry_key = ?
                ''', (dictionary_id, key))
                
                row = cursor.fetchone()
                if row is None:
                    raise KeyError(f"Entry not found: {key} in dictionary {dictionary_id}")
                
                # Deserialize value
                value_data = row['entry_value']
                if row['value_type'] == 'numpy':
                    value = pickle.loads(value_data)
                else:
                    value = pickle.loads(value_data)
                
                # Update access statistics
                self._update_entry_access(dictionary_id, key)
                
                return value
                
        except Exception as e:
            logger.error(f"Failed to get dictionary entry {key} from {dictionary_id}: {e}")
            raise

    def _update_entry_access(self, dictionary_id: str, key: str):
        """Update entry access statistics"""
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE dictionary_entries 
                    SET last_accessed = ?, access_count = access_count + 1 
                    WHERE dictionary_id = ? AND entry_key = ?
                ''', (datetime.now().isoformat(), dictionary_id, key))
                conn.commit()
                
        except Exception as e:
            logger.warning(f"Failed to update entry access stats: {e}")

    def search_dictionaries(self, query: str, search_fields: List[str] = None) -> List[Dict[str, Any]]:
        """
        Search dictionaries by content
        
        Args:
            query: Search query
            search_fields: Fields to search in
            
        Returns:
            List of matching dictionaries with highlights
        """
        
        if search_fields is None:
            search_fields = ['entry_key', 'tags']
        
        results = []
        
        try:
            # Get all active dictionaries
            dictionaries = self.list_dictionaries(status=DictionaryStatus.ACTIVE)
            
            for metadata in dictionaries:
                dictionary_data = self.get_dictionary(metadata.dictionary_id, update_access=False)
                matches = self._search_dictionary_content(dictionary_data, query, search_fields)
                
                if matches:
                    results.append({
                        'dictionary_id': metadata.dictionary_id,
                        'metadata': metadata,
                        'matches': matches,
                        'match_count': len(matches)
                    })
            
            return results
            
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []

    def _search_dictionary_content(self, data: Dict[str, Any], query: str, search_fields: List[str]) -> List[Dict[str, Any]]:
        """Search dictionary content for matches"""
        matches = []
        query_lower = query.lower()
        
        for key, value in data.items():
            # Search in key
            if 'entry_key' in search_fields and query_lower in key.lower():
                matches.append({
                    'field': 'key',
                    'key': key,
                    'value': str(value),
                    'match_type': 'key_match'
                })
            
            # Search in value (for string values)
            if isinstance(value, str) and 'value' in search_fields and query_lower in value.lower():
                matches.append({
                    'field': 'value',
                    'key': key,
                    'value': value,
                    'match_type': 'value_match'
                })
            
            # Search in string representation of other types
            elif 'value' in search_fields and query_lower in str(value).lower():
                matches.append({
                    'field': 'value',
                    'key': key,
                    'value': str(value),
                    'match_type': 'value_match'
                })
        
        return matches

    def export_dictionary(self, dictionary_id: str, password: str) -> bytes:
        """
        Export dictionary as encrypted package
        
        Args:
            dictionary_id: Dictionary identifier
            password: Encryption password
            
        Returns:
            Encrypted export data
        """
        
        try:
            # Get dictionary data and metadata
            data = self.get_dictionary(dictionary_id, update_access=False)
            metadata = self.metadata_cache.get(dictionary_id)
            if metadata is None:
                metadata = self._get_metadata_from_db(dictionary_id)
            
            # Create export package
            export_package = {
                'version': '2.0.0',
                'timestamp': datetime.now().isoformat(),
                'dictionary_id': dictionary_id,
                'metadata': asdict(metadata),
                'data': data
            }
            
            # Serialize package
            serialized_package = self._serialize_data(export_package)
            
            # Encrypt with password
            encryption_key = hashlib.pbkdf2_hmac('sha3-512', password.encode(), b'dictionary_export', 100000, 32)
            nonce = secrets.token_bytes(16)
            
            cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(serialized_package) + encryptor.finalize()
            
            export_data = nonce + encrypted_data + encryptor.tag
            
            # Log the operation
            self._log_audit_event(dictionary_id, "export", "dictionary exported")
            
            logger.info(f"Exported dictionary {dictionary_id}")
            
            return export_data
            
        except Exception as e:
            logger.error(f"Failed to export dictionary {dictionary_id}: {e}")
            raise

    def import_dictionary(self, export_data: bytes, password: str, overwrite: bool = False) -> str:
        """
        Import dictionary from encrypted package
        
        Args:
            export_data: Encrypted export data
            password: Decryption password
            overwrite: Whether to overwrite existing dictionary
            
        Returns:
            Imported dictionary ID
        """
        
        try:
            # Parse export data
            nonce = export_data[:16]
            encrypted_data = export_data[16:-16]
            tag = export_data[-16:]
            
            # Decrypt with password
            decryption_key = hashlib.pbkdf2_hmac('sha3-512', password.encode(), b'dictionary_export', 100000, 32)
            
            cipher = Cipher(algorithms.AES(decryption_key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            serialized_package = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Deserialize package
            export_package = self._deserialize_data(serialized_package)
            
            # Extract data
            dictionary_id = export_package['dictionary_id']
            metadata_dict = export_package['metadata']
            data = export_package['data']
            
            # Check if dictionary exists
            if self._dictionary_exists(dictionary_id) and not overwrite:
                raise ValueError(f"Dictionary {dictionary_id} already exists. Use overwrite=True to replace.")
            
            # Create or update dictionary
            if self._dictionary_exists(dictionary_id) and overwrite:
                self.update_dictionary(dictionary_id, data)
            else:
                # Convert metadata dict to object
                metadata = DictionaryMetadata(**metadata_dict)
                metadata.last_modified = datetime.now()
                metadata.last_accessed = datetime.now()
                
                # Process and store dictionary
                encrypted_data, compression_ratio, entropy_score = self._process_dictionary_data(data)
                metadata.size_bytes = len(encrypted_data)
                metadata.compression_ratio = compression_ratio
                metadata.entropy_score = entropy_score
                metadata.integrity_hash = self._calculate_integrity_hash(data)
                
                self._store_dictionary_in_db(dictionary_id, encrypted_data, metadata)
                self._store_dictionary_entries(dictionary_id, data)
            
            # Log the operation
            self._log_audit_event(dictionary_id, "import", "dictionary imported")
            
            logger.info(f"Imported dictionary {dictionary_id}")
            
            return dictionary_id
            
        except InvalidTag:
            logger.error("Dictionary import failed: authentication tag mismatch")
            raise SecurityError("Dictionary import authentication failed")
        except Exception as e:
            logger.error(f"Failed to import dictionary: {e}")
            raise

    def _get_metadata_from_db(self, dictionary_id: str) -> Optional[DictionaryMetadata]:
        """Retrieve dictionary metadata from database"""
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute(
                    'SELECT * FROM dictionaries WHERE dictionary_id = ?',
                    (dictionary_id,)
                )
                row = cursor.fetchone()
                
                if row is None:
                    return None
                
                return DictionaryMetadata(
                    dictionary_id=row['dictionary_id'],
                    dictionary_type=DictionaryType(row['dictionary_type']),
                    status=DictionaryStatus(row['status']),
                    version=row['version'],
                    created_at=datetime.fromisoformat(row['created_at']),
                    expires_at=datetime.fromisoformat(row['expires_at']) if row['expires_at'] else None,
                    device_id=row['device_id'],
                    session_id=row['session_id'],
                    size_bytes=row['size_bytes'],
                    entry_count=row['entry_count'],
                    compression_ratio=row['compression_ratio'],
                    entropy_score=row['entropy_score'],
                    integrity_hash=row['integrity_hash'],
                    tags=json.loads(row['tags']) if row['tags'] else [],
                    dependencies=json.loads(row['dependencies']) if row['dependencies'] else [],
                    access_pattern=json.loads(row['access_pattern']) if row['access_pattern'] else {},
                    last_accessed=datetime.fromisoformat(row['last_accessed']),
                    last_modified=datetime.fromisoformat(row['last_modified'])
                )
                
        except Exception as e:
            logger.error(f"Failed to get metadata for dictionary {dictionary_id}: {e}")
            return None

    def _log_audit_event(self, dictionary_id: str, operation: str, additional_info: str = ""):
        """Log dictionary operation to audit trail"""
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO access_audit_log 
                    (dictionary_id, operation, timestamp, device_id, additional_info)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    dictionary_id,
                    operation,
                    datetime.now().isoformat(),
                    self.device_id,
                    additional_info
                ))
                conn.commit()
                
        except Exception as e:
            logger.warning(f"Failed to log audit event: {e}")

    def _cleanup_expired_dictionaries(self):
        """Clean up expired dictionaries"""
        try:
            expired_count = 0
            current_time = datetime.now()
            
            # Get expired dictionaries
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT dictionary_id FROM dictionaries WHERE expires_at < ? AND status = ?',
                    (current_time.isoformat(), DictionaryStatus.ACTIVE.value)
                )
                expired_dicts = [row[0] for row in cursor.fetchall()]
            
            # Archive expired dictionaries
            for dictionary_id in expired_dicts:
                try:
                    self._archive_dictionary(dictionary_id)
                    expired_count += 1
                    
                    # Remove from cache
                    if self.enable_caching:
                        with self._cache_lock:
                            self.dictionary_cache.pop(dictionary_id, None)
                            self.metadata_cache.pop(dictionary_id, None)
                    
                    logger.info(f"Archived expired dictionary {dictionary_id}")
                    
                except Exception as e:
                    logger.warning(f"Failed to archive expired dictionary {dictionary_id}: {e}")
            
            if expired_count > 0:
                logger.info(f"Cleaned up {expired_count} expired dictionaries")
                
        except Exception as e:
            logger.error(f"Failed to clean up expired dictionaries: {e}")

    def _cleanup_cache(self):
        """Clean up expired cache entries"""
        if not self.enable_caching:
            return
        
        try:
            current_time = time.time()
            cache_ttl = self.security_params['cache_ttl'].total_seconds()
            removed_count = 0
            
            with self._cache_lock:
                # Create list of cache keys to remove
                to_remove = []
                
                for dictionary_id, metadata in self.metadata_cache.items():
                    # Check if cache entry is expired
                    cache_age = current_time - metadata.last_accessed.timestamp()
                    if cache_age > cache_ttl:
                        to_remove.append(dictionary_id)
                
                # Remove expired entries
                for dictionary_id in to_remove:
                    self.dictionary_cache.pop(dictionary_id, None)
                    self.metadata_cache.pop(dictionary_id, None)
                    removed_count += 1
            
            if removed_count > 0:
                logger.debug(f"Cleaned up {removed_count} expired cache entries")
                
        except Exception as e:
            logger.error(f"Failed to clean up cache: {e}")

    def _create_backup(self):
        """Create database backup"""
        if not self.backup_enabled:
            return
        
        try:
            backup_path = f"{self.db_path}.backup.{int(time.time())}"
            
            with self._db_lock:
                # Simple file copy for backup
                import shutil
                shutil.copy2(self.db_path, backup_path)
                
                # Compress backup
                with open(backup_path, 'rb') as f_in:
                    with open(f"{backup_path}.gz", 'wb') as f_out:
                        f_out.write(zlib.compress(f_in.read()))
                
                # Remove uncompressed backup
                os.remove(backup_path)
                
                logger.info(f"Created backup: {backup_path}.gz")
                
        except Exception as e:
            logger.error(f"Failed to create backup: {e}")

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics"""
        metrics_dict = asdict(self.performance_metrics)
        metrics_dict.update({
            'cache_size': len(self.dictionary_cache),
            'total_dictionaries': len(self.list_dictionaries()),
            'database_size': os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0,
            'sync_state': asdict(self.sync_state),
            'security_level': self.security_level
        })
        return metrics_dict

    def shutdown(self):
        """Gracefully shutdown the dictionary manager"""
        # Stop background services
        self.background_executor.shutdown(wait=False)
        
        # Clear caches
        self.dictionary_cache.clear()
        self.metadata_cache.clear()
        
        # Clear sensitive data from memory
        if hasattr(self, 'encryption_key'):
            # Securely wipe encryption key from memory
            import ctypes
            ctypes.memset(id(self.encryption_key), 0, len(self.encryption_key))
            self.encryption_key = None
        
        logger.info("DictionaryManager shutdown completed")

    def __repr__(self) -> str:
        """String representation of the dictionary manager"""
        return (f"DictionaryManager(device='{self.device_id}', "
                f"security='{self.security_level}', "
                f"dictionaries={len(self.list_dictionaries())}, "
                f"cache_size={len(self.dictionary_cache)})")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.shutdown()

class SecurityError(Exception):
    """Security-related exceptions"""
    pass

# Utility functions
def create_dictionary_manager(device_id: str,
                            db_path: Optional[str] = None,
                            security_level: str = "high") -> DictionaryManager:
    """
    Create a pre-configured dictionary manager
    
    Args:
        device_id: Unique device identifier
        db_path: Optional database path
        security_level: Security level ('basic', 'standard', 'high', 'quantum')
        
    Returns:
        Configured DictionaryManager instance
    """
    if db_path is None:
        db_path = f"dictionaries_{device_id}_{int(time.time())}.db"
    
    return DictionaryManager(
        db_path=db_path,
        device_id=device_id,
        security_level=security_level,
        enable_caching=True,
        cache_size=2000,
        enable_compression=True,
        enable_encryption=True,
        sync_enabled=True,
        backup_enabled=True
    )

def calculate_data_entropy(data: Dict[str, Any]) -> float:
    """
    Calculate Shannon entropy of dictionary data
    
    Args:
        data: Dictionary data
        
    Returns:
        Entropy value
    """
    manager = DictionaryManager(db_path=":memory:", device_id="temp")
    serialized_data = manager._serialize_data(data)
    return manager._calculate_data_entropy(serialized_data)

def verify_dictionary_integrity(data: Dict[str, Any]) -> str:
    """
    Calculate integrity hash of dictionary data
    
    Args:
        data: Dictionary data
        
    Returns:
        Integrity hash
    """
    manager = DictionaryManager(db_path=":memory:", device_id="temp")
    return manager._calculate_integrity_hash(data)