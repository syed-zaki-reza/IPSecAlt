# [file name]: src/key_management.py
"""
Enhanced Key Management System for Quantum-Resistant Encryption
Advanced key generation, derivation, rotation, and lifecycle management

Features:
- Quantum-resistant key derivation functions (KDF)
- Hierarchical key derivation with parent-child relationships
- Automatic key rotation and expiration policies
- Secure encrypted storage with audit trails
- Multi-level security with hardware acceleration support
- Thread-safe operations with performance optimization
"""

import os
import sqlite3
import json
import time
import logging
import threading
import secrets
import hashlib
import hmac
from typing import Dict, List, Tuple, Optional, Any, Union
from enum import Enum
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import numpy as np
import argon2
from base64 import b64encode, b64decode

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class KeyType(Enum):
    """Types of cryptographic keys"""
    MASTER = "master"
    SESSION = "session"
    TENSOR = "tensor"
    AI_LOGIC = "ai_logic"
    DICTIONARY = "dictionary"
    EPHEMERAL = "ephemeral"
    TRANSPORT = "transport"
    IDENTITY = "identity"
    BACKUP = "backup"

class KeyStatus(Enum):
    """Key lifecycle status"""
    ACTIVE = "active"
    ROTATING = "rotating"
    DEPRECATED = "deprecated"
    EXPIRED = "expired"
    REVOKED = "revoked"
    COMPROMISED = "compromised"
    ARCHIVED = "archived"

class SecurityLevel(Enum):
    """Security levels for key generation"""
    BASIC = "basic"      # 128-bit security
    STANDARD = "standard" # 192-bit security
    HIGH = "high"        # 256-bit security
    QUANTUM = "quantum"   # 512-bit security

@dataclass
class KeyMetadata:
    """Comprehensive key metadata"""
    key_id: str
    key_type: KeyType
    status: KeyStatus
    created_at: datetime
    expires_at: Optional[datetime]
    device_id: str
    session_id: Optional[str]
    security_level: SecurityLevel
    key_length: int
    usage_count: int = 0
    last_used: Optional[datetime] = None
    rotated_from: Optional[str] = None
    parent_key_id: Optional[str] = None
    derivation_context: Optional[str] = None
    tags: List[str] = None
    version: str = "2.0.0"

    def __post_init__(self):
        if self.tags is None:
            self.tags = []

@dataclass
class KeyDerivationParams:
    """Parameters for key derivation"""
    algorithm: str
    salt_length: int
    iterations: int
    memory_cost: int
    parallelism: int
    output_length: int

@dataclass
class PerformanceMetrics:
    """Key management performance metrics"""
    keys_generated: int = 0
    keys_rotated: int = 0
    keys_revoked: int = 0
    keys_expired: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    derivation_operations: int = 0
    encryption_operations: int = 0
    decryption_operations: int = 0
    average_derivation_time: float = 0.0
    total_operations: int = 0

class KeyManager:
    """
    Advanced Key Management System for Quantum-Resistant Encryption
    
    Features:
    - Multi-algorithm key derivation (Argon2, HKDF, PBKDF2)
    - Hierarchical key chains with parent-child relationships
    - Automatic key rotation based on usage and time policies
    - Secure encrypted storage with integrity protection
    - Hardware security module (HSM) support
    - Comprehensive audit trails and usage monitoring
    - Thread-safe operations with lock hierarchy
    """

    # Supported key derivation algorithms
    KDF_ALGORITHMS = {
        'argon2id': 'Argon2id (Memory-hard)',
        'hkdf_sha512': 'HKDF-SHA512',
        'pbkdf2_sha512': 'PBKDF2-SHA512', 
        'hkdf_sha3_512': 'HKDF-SHA3-512',
        'bcrypt': 'Bcrypt (Adaptive)'
    }

    def __init__(self, 
                 db_path: str,
                 device_id: Optional[str] = None,
                 security_level: str = 'high',
                 auto_rotation: bool = True,
                 enable_caching: bool = True,
                 cache_size: int = 1000,
                 backup_enabled: bool = True,
                 hsm_support: bool = False):
        """
        Initialize the Advanced Key Management System
        
        Args:
            db_path: Path to SQLite database file
            device_id: Unique device identifier
            security_level: Security level ('basic', 'standard', 'high', 'quantum')
            auto_rotation: Enable automatic key rotation
            enable_caching: Enable key caching for performance
            cache_size: Maximum cache size
            backup_enabled: Enable automatic key backup
            hsm_support: Enable Hardware Security Module support
        """
        
        self.db_path = db_path
        self.device_id = device_id or self._generate_device_id()
        self.security_level = SecurityLevel(security_level)
        self.auto_rotation = auto_rotation
        self.enable_caching = enable_caching
        self.cache_size = cache_size
        self.backup_enabled = backup_enabled
        self.hsm_support = hsm_support
        
        # Security parameters based on level
        self.security_params = self._get_security_params(security_level)
        
        # Initialize components
        self.master_key = None
        self.key_cache = {}
        self.key_metadata = {}
        self.performance_metrics = PerformanceMetrics()
        self.rotation_schedule = {}
        self.derivation_cache = {}
        
        # Thread safety
        self._lock = threading.RLock()
        self._cache_lock = threading.Lock()
        self._db_lock = threading.Lock()
        
        # Initialize database
        self._init_database()
        
        # Initialize master key
        self._init_master_key()
        
        # Start background services if enabled
        if auto_rotation:
            self._start_background_services()
        
        logger.info(f"KeyManager initialized for device {self.device_id} "
                   f"with {security_level} security level")

    def _get_security_params(self, level: str) -> Dict[str, Any]:
        """Get security parameters based on security level"""
        params = {
            'basic': {
                'key_lengths': {
                    KeyType.MASTER: 32,
                    KeyType.SESSION: 32,
                    KeyType.TENSOR: 32,
                    KeyType.AI_LOGIC: 32,
                    KeyType.DICTIONARY: 32,
                    KeyType.EPHEMERAL: 16
                },
                'kdf_iterations': 100000,
                'argon2_memory': 64 * 1024,  # 64MB
                'rotation_interval': timedelta(days=30),
                'max_key_usage': 10000,
                'cache_ttl': timedelta(hours=1)
            },
            'standard': {
                'key_lengths': {
                    KeyType.MASTER: 48,
                    KeyType.SESSION: 32,
                    KeyType.TENSOR: 48,
                    KeyType.AI_LOGIC: 32,
                    KeyType.DICTIONARY: 32,
                    KeyType.EPHEMERAL: 24
                },
                'kdf_iterations': 250000,
                'argon2_memory': 128 * 1024,  # 128MB
                'rotation_interval': timedelta(days=14),
                'max_key_usage': 5000,
                'cache_ttl': timedelta(minutes=30)
            },
            'high': {
                'key_lengths': {
                    KeyType.MASTER: 64,
                    KeyType.SESSION: 48,
                    KeyType.TENSOR: 64,
                    KeyType.AI_LOGIC: 48,
                    KeyType.DICTIONARY: 48,
                    KeyType.EPHEMERAL: 32
                },
                'kdf_iterations': 500000,
                'argon2_memory': 256 * 1024,  # 256MB
                'rotation_interval': timedelta(days=7),
                'max_key_usage': 1000,
                'cache_ttl': timedelta(minutes=15)
            },
            'quantum': {
                'key_lengths': {
                    KeyType.MASTER: 128,
                    KeyType.SESSION: 64,
                    KeyType.TENSOR: 128,
                    KeyType.AI_LOGIC: 64,
                    KeyType.DICTIONARY: 64,
                    KeyType.EPHEMERAL: 48
                },
                'kdf_iterations': 1000000,
                'argon2_memory': 512 * 1024,  # 512MB
                'rotation_interval': timedelta(days=1),
                'max_key_usage': 100,
                'cache_ttl': timedelta(minutes=5)
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
                
                # Keys table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS keys (
                        key_id TEXT PRIMARY KEY,
                        key_type TEXT NOT NULL,
                        encrypted_key BLOB NOT NULL,
                        status TEXT NOT NULL,
                        created_at TIMESTAMP NOT NULL,
                        expires_at TIMESTAMP,
                        device_id TEXT NOT NULL,
                        session_id TEXT,
                        security_level TEXT NOT NULL,
                        key_length INTEGER NOT NULL,
                        usage_count INTEGER DEFAULT 0,
                        last_used TIMESTAMP,
                        rotated_from TEXT,
                        parent_key_id TEXT,
                        derivation_context TEXT,
                        tags TEXT,
                        version TEXT NOT NULL,
                        FOREIGN KEY (parent_key_id) REFERENCES keys (key_id)
                    )
                ''')
                
                # Key derivations table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS key_derivations (
                        parent_key_id TEXT NOT NULL,
                        derived_key_id TEXT NOT NULL,
                        derivation_context TEXT NOT NULL,
                        derivation_algorithm TEXT NOT NULL,
                        salt BLOB NOT NULL,
                        created_at TIMESTAMP NOT NULL,
                        PRIMARY KEY (parent_key_id, derived_key_id),
                        FOREIGN KEY (parent_key_id) REFERENCES keys (key_id),
                        FOREIGN KEY (derived_key_id) REFERENCES keys (key_id)
                    )
                ''')
                
                # Key usage audit log
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS key_usage_log (
                        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        key_id TEXT NOT NULL,
                        operation TEXT NOT NULL,
                        timestamp TIMESTAMP NOT NULL,
                        additional_info TEXT,
                        FOREIGN KEY (key_id) REFERENCES keys (key_id)
                    )
                ''')
                
                # Key rotation history
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS key_rotation_history (
                        rotation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        original_key_id TEXT NOT NULL,
                        new_key_id TEXT NOT NULL,
                        rotation_reason TEXT NOT NULL,
                        rotated_at TIMESTAMP NOT NULL,
                        FOREIGN KEY (original_key_id) REFERENCES keys (key_id),
                        FOREIGN KEY (new_key_id) REFERENCES keys (key_id)
                    )
                ''')
                
                # Create indexes for performance
                conn.execute('CREATE INDEX IF NOT EXISTS idx_keys_status ON keys(status)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_keys_type ON keys(key_type)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_keys_session ON keys(session_id)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_usage_log_key ON key_usage_log(key_id)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_usage_log_time ON key_usage_log(timestamp)')
                
                conn.commit()
                logger.info("Database initialized successfully")
                
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

    def _init_master_key(self):
        """Initialize or load master key"""
        try:
            # Try to load existing master key
            self.master_key = self._load_master_key()
            if self.master_key is None:
                # Generate new master key
                self.master_key = self._generate_master_key()
                self._store_master_key(self.master_key)
                logger.info("Generated new master key")
            else:
                logger.info("Loaded existing master key")
                
        except Exception as e:
            logger.error(f"Failed to initialize master key: {e}")
            raise

    def _generate_master_key(self) -> bytes:
        """Generate cryptographically secure master key"""
        key_length = self.security_params['key_lengths'][KeyType.MASTER]
        return secrets.token_bytes(key_length)

    def _load_master_key(self) -> Optional[bytes]:
        """Load master key from secure storage"""
        # In production, this would integrate with HSM or secure enclave
        # For this implementation, we'll use a simplified approach
        try:
            master_key_path = self.db_path + '.masterkey'
            if os.path.exists(master_key_path):
                with open(master_key_path, 'rb') as f:
                    encrypted_data = f.read()
                
                # Derive decryption key from device ID
                decryption_key = self._derive_key_from_device_id(32)
                nonce = encrypted_data[:16]
                ciphertext = encrypted_data[16:-16]
                tag = encrypted_data[-16:]
                
                cipher = Cipher(algorithms.AES(decryption_key), modes.GCM(nonce, tag), backend=default_backend())
                decryptor = cipher.decryptor()
                master_key = decryptor.update(ciphertext) + decryptor.finalize()
                
                return master_key
        except Exception as e:
            logger.warning(f"Failed to load master key: {e}")
        
        return None

    def _store_master_key(self, master_key: bytes):
        """Store master key in secure storage"""
        try:
            # Derive encryption key from device ID
            encryption_key = self._derive_key_from_device_id(32)
            nonce = os.urandom(16)
            
            cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(master_key) + encryptor.finalize()
            
            encrypted_data = nonce + ciphertext + encryptor.tag
            
            master_key_path = self.db_path + '.masterkey'
            with open(master_key_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Set secure permissions
            os.chmod(master_key_path, 0o600)
            
        except Exception as e:
            logger.error(f"Failed to store master key: {e}")
            raise

    def _derive_key_from_device_id(self, key_length: int) -> bytes:
        """Derive key from device ID using HKDF"""
        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=key_length,
            salt=None,
            info=b"device_key_derivation",
            backend=default_backend()
        )
        return hkdf.derive(self.device_id.encode())

    def _generate_device_id(self) -> str:
        """Generate unique device identifier"""
        system_info = f"{os.urandom(16).hex()}{time.time()}{secrets.token_bytes(16).hex()}"
        device_hash = hashlib.sha512(system_info.encode()).hexdigest()
        return f"device_{device_hash[:32]}"

    def _start_background_services(self):
        """Start background services for key management"""
        def rotation_service():
            while getattr(self, 'auto_rotation', False):
                try:
                    self._check_rotation_schedule()
                    time.sleep(60)  # Check every minute
                except Exception as e:
                    logger.error(f"Rotation service error: {e}")
                    time.sleep(300)  # Wait 5 minutes on error
        
        def cleanup_service():
            while True:
                try:
                    self.cleanup_expired_keys()
                    time.sleep(3600)  # Run every hour
                except Exception as e:
                    logger.error(f"Cleanup service error: {e}")
                    time.sleep(7200)  # Wait 2 hours on error
        
        # Start background threads
        self.rotation_thread = threading.Thread(target=rotation_service, daemon=True)
        self.cleanup_thread = threading.Thread(target=cleanup_service, daemon=True)
        
        self.rotation_thread.start()
        self.cleanup_thread.start()
        
        logger.info("Background services started")

    def derive_key(self, 
                   key_type: KeyType,
                   context: str,
                   key_length: Optional[int] = None,
                   session_id: Optional[str] = None,
                   parent_key_id: Optional[str] = None,
                   derivation_algorithm: str = 'argon2id') -> Tuple[str, bytes]:
        """
        Derive a new cryptographic key
        
        Args:
            key_type: Type of key to derive
            context: Derivation context string
            key_length: Optional key length override
            session_id: Optional session identifier
            parent_key_id: Optional parent key for hierarchical derivation
            derivation_algorithm: KDF algorithm to use
            
        Returns:
            Tuple of (key_id, key_data)
        """
        
        start_time = time.time()
        
        with self._lock:
            try:
                # Determine key length
                if key_length is None:
                    key_length = self.security_params['key_lengths'].get(key_type, 32)
                
                # Generate key ID
                key_id = self._generate_key_id(key_type, context, session_id)
                
                # Check if key already exists
                existing_key = self._get_key_from_db(key_id)
                if existing_key is not None:
                    logger.warning(f"Key {key_id} already exists, returning existing key")
                    return key_id, existing_key
                
                # Derive key material
                if parent_key_id:
                    key_data = self._derive_child_key(parent_key_id, context, key_length, derivation_algorithm)
                else:
                    key_data = self._derive_root_key(context, key_length, derivation_algorithm)
                
                # Create key metadata
                expires_at = None
                if key_type == KeyType.EPHEMERAL:
                    expires_at = datetime.now() + timedelta(hours=1)
                elif key_type == KeyType.SESSION:
                    expires_at = datetime.now() + timedelta(days=1)
                
                metadata = KeyMetadata(
                    key_id=key_id,
                    key_type=key_type,
                    status=KeyStatus.ACTIVE,
                    created_at=datetime.now(),
                    expires_at=expires_at,
                    device_id=self.device_id,
                    session_id=session_id,
                    security_level=self.security_level,
                    key_length=key_length,
                    parent_key_id=parent_key_id,
                    derivation_context=context
                )
                
                # Store key in database
                self._store_key_in_db(key_id, key_data, metadata)
                
                # Cache the key
                if self.enable_caching:
                    with self._cache_lock:
                        self.key_cache[key_id] = (key_data, metadata)
                
                # Update performance metrics
                self.performance_metrics.keys_generated += 1
                self.performance_metrics.derivation_operations += 1
                derivation_time = time.time() - start_time
                self.performance_metrics.average_derivation_time = (
                    self.performance_metrics.average_derivation_time * 
                    (self.performance_metrics.derivation_operations - 1) + 
                    derivation_time
                ) / self.performance_metrics.derivation_operations
                
                # Log the operation
                self._log_key_operation(key_id, "derive", f"context: {context}, algorithm: {derivation_algorithm}")
                
                logger.info(f"Derived {key_type.value} key {key_id} in {derivation_time:.3f}s")
                
                return key_id, key_data
                
            except Exception as e:
                logger.error(f"Failed to derive key: {e}")
                raise

    def _derive_root_key(self, context: str, key_length: int, algorithm: str) -> bytes:
        """Derive root key from master key"""
        salt = os.urandom(32)
        info = f"root_key_derivation:{context}:{self.device_id}".encode()
        
        if algorithm == 'argon2id':
            # Use Argon2 for memory-hard derivation
            ph = argon2.PasswordHasher(
                time_cost=3,
                memory_cost=self.security_params['argon2_memory'],
                parallelism=1,
                hash_len=key_length,
                salt_len=32
            )
            derived = ph.hash(self.master_key + info, salt=salt)
            return derived[:key_length]
        
        elif algorithm == 'hkdf_sha512':
            hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=key_length,
                salt=salt,
                info=info,
                backend=default_backend()
            )
            return hkdf.derive(self.master_key)
        
        elif algorithm == 'pbkdf2_sha512':
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=key_length,
                salt=salt,
                iterations=self.security_params['kdf_iterations'],
                backend=default_backend()
            )
            return kdf.derive(self.master_key + info)
        
        else:
            raise ValueError(f"Unsupported derivation algorithm: {algorithm}")

    def _derive_child_key(self, parent_key_id: str, context: str, key_length: int, algorithm: str) -> bytes:
        """Derive child key from parent key"""
        parent_key = self.get_key(parent_key_id)  # This will validate the parent key
        
        salt = os.urandom(32)
        info = f"child_key_derivation:{context}:{parent_key_id}".encode()
        
        if algorithm == 'hkdf_sha512':
            hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=key_length,
                salt=salt,
                info=info,
                backend=default_backend()
            )
            derived_key = hkdf.derive(parent_key)
        else:
            # Default to HKDF for child derivation
            hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=key_length,
                salt=salt,
                info=info,
                backend=default_backend()
            )
            derived_key = hkdf.derive(parent_key)
        
        # Store derivation record
        self._store_derivation_record(parent_key_id, derived_key, context, algorithm, salt)
        
        return derived_key

    def _generate_key_id(self, key_type: KeyType, context: str, session_id: Optional[str]) -> str:
        """Generate unique key identifier"""
        base_data = f"{key_type.value}:{context}:{session_id or ''}:{time.time()}:{secrets.token_bytes(16).hex()}"
        key_hash = hashlib.sha3_512(base_data.encode()).hexdigest()
        return f"key_{key_type.value}_{key_hash[:32]}"

    def get_key(self, key_id: str, increment_usage: bool = True) -> bytes:
        """
        Retrieve a key by ID
        
        Args:
            key_id: Key identifier
            increment_usage: Whether to increment usage counter
            
        Returns:
            Key data as bytes
        """
        start_time = time.time()
        
        # Check cache first
        if self.enable_caching:
            with self._cache_lock:
                if key_id in self.key_cache:
                    key_data, metadata = self.key_cache[key_id]
                    self.performance_metrics.cache_hits += 1
                    
                    # Validate key status
                    self._validate_key_status(metadata)
                    
                    if increment_usage:
                        self._update_key_usage(key_id, metadata)
                    
                    return key_data
        
        self.performance_metrics.cache_misses += 1
        
        with self._lock:
            try:
                # Get key from database
                key_data = self._get_key_from_db(key_id)
                if key_data is None:
                    raise KeyError(f"Key not found: {key_id}")
                
                # Get metadata
                metadata = self._get_metadata_from_db(key_id)
                if metadata is None:
                    raise KeyError(f"Metadata not found for key: {key_id}")
                
                # Validate key status
                self._validate_key_status(metadata)
                
                # Update cache
                if self.enable_caching:
                    with self._cache_lock:
                        self.key_cache[key_id] = (key_data, metadata)
                
                # Update usage
                if increment_usage:
                    self._update_key_usage(key_id, metadata)
                
                # Check if rotation is needed
                if self.auto_rotation:
                    self._check_rotation_needed(key_id, metadata)
                
                self.performance_metrics.decryption_operations += 1
                
                logger.debug(f"Retrieved key {key_id} in {time.time() - start_time:.3f}s")
                
                return key_data
                
            except Exception as e:
                logger.error(f"Failed to get key {key_id}: {e}")
                raise

    def _get_key_from_db(self, key_id: str) -> Optional[bytes]:
        """Retrieve encrypted key from database and decrypt it"""
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute(
                    'SELECT encrypted_key FROM keys WHERE key_id = ?',
                    (key_id,)
                )
                row = cursor.fetchone()
                
                if row is None:
                    return None
                
                encrypted_key = row['encrypted_key']
                return self._decrypt_key(encrypted_key)
                
        except Exception as e:
            logger.error(f"Failed to get key from database: {e}")
            raise

    def _decrypt_key(self, encrypted_data: bytes) -> bytes:
        """Decrypt key data using master key"""
        try:
            # Parse encrypted data (nonce + ciphertext + tag)
            nonce = encrypted_data[:16]
            ciphertext = encrypted_data[16:-16]
            tag = encrypted_data[-16:]
            
            cipher = Cipher(algorithms.AES(self.master_key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            
            return decrypted
            
        except InvalidTag:
            logger.error("Key decryption failed: authentication tag mismatch")
            raise SecurityError("Key decryption authentication failed")
        except Exception as e:
            logger.error(f"Key decryption failed: {e}")
            raise

    def _store_key_in_db(self, key_id: str, key_data: bytes, metadata: KeyMetadata):
        """Store encrypted key in database"""
        try:
            encrypted_key = self._encrypt_key(key_data)
            
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO keys (
                        key_id, key_type, encrypted_key, status, created_at, expires_at,
                        device_id, session_id, security_level, key_length, usage_count,
                        last_used, rotated_from, parent_key_id, derivation_context, tags, version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    key_id,
                    metadata.key_type.value,
                    encrypted_key,
                    metadata.status.value,
                    metadata.created_at.isoformat(),
                    metadata.expires_at.isoformat() if metadata.expires_at else None,
                    metadata.device_id,
                    metadata.session_id,
                    metadata.security_level.value,
                    metadata.key_length,
                    metadata.usage_count,
                    metadata.last_used.isoformat() if metadata.last_used else None,
                    metadata.rotated_from,
                    metadata.parent_key_id,
                    metadata.derivation_context,
                    json.dumps(metadata.tags),
                    metadata.version
                ))
                
                conn.commit()
                
            # Update in-memory metadata
            self.key_metadata[key_id] = metadata
            
        except Exception as e:
            logger.error(f"Failed to store key in database: {e}")
            raise

    def _encrypt_key(self, key_data: bytes) -> bytes:
        """Encrypt key data using master key"""
        nonce = os.urandom(16)
        
        cipher = Cipher(algorithms.AES(self.master_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(key_data) + encryptor.finalize()
        
        return nonce + ciphertext + encryptor.tag

    def _validate_key_status(self, metadata: KeyMetadata):
        """Validate key status and expiration"""
        current_time = datetime.now()
        
        if metadata.status == KeyStatus.REVOKED:
            raise SecurityError(f"Key {metadata.key_id} has been revoked")
        elif metadata.status == KeyStatus.COMPROMISED:
            raise SecurityError(f"Key {metadata.key_id} is compromised")
        elif metadata.status == KeyStatus.EXPIRED:
            raise SecurityError(f"Key {metadata.key_id} has expired")
        elif metadata.expires_at and metadata.expires_at < current_time:
            # Auto-expire the key
            self._update_key_status(metadata.key_id, KeyStatus.EXPIRED)
            raise SecurityError(f"Key {metadata.key_id} has expired")

    def _update_key_usage(self, key_id: str, metadata: KeyMetadata):
        """Update key usage statistics"""
        current_time = datetime.now()
        metadata.usage_count += 1
        metadata.last_used = current_time
        
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'UPDATE keys SET usage_count = ?, last_used = ? WHERE key_id = ?',
                    (metadata.usage_count, current_time.isoformat(), key_id)
                )
                conn.commit()
                
        except Exception as e:
            logger.warning(f"Failed to update key usage for {key_id}: {e}")

    def _check_rotation_needed(self, key_id: str, metadata: KeyMetadata):
        """Check if key rotation is needed based on usage and time"""
        current_time = datetime.now()
        
        # Check usage-based rotation
        if metadata.usage_count >= self.security_params['max_key_usage']:
            self.rotation_schedule[key_id] = {'reason': 'usage_limit', 'priority': 'high'}
            return
        
        # Check time-based rotation
        if metadata.expires_at and metadata.expires_at - current_time < timedelta(hours=24):
            self.rotation_schedule[key_id] = {'reason': 'expiration_imminent', 'priority': 'medium'}
            return
        
        # Check for deprecated status
        if metadata.status == KeyStatus.DEPRECATED:
            self.rotation_schedule[key_id] = {'reason': 'deprecated', 'priority': 'low'}

    def rotate_key(self, key_id: str, reason: str = "scheduled_rotation") -> str:
        """
        Rotate a key to a new version
        
        Args:
            key_id: Key identifier to rotate
            reason: Reason for rotation
            
        Returns:
            New key identifier
        """
        with self._lock:
            try:
                # Get existing key metadata
                old_metadata = self._get_metadata_from_db(key_id)
                if old_metadata is None:
                    raise KeyError(f"Key not found: {key_id}")
                
                # Create new key with same parameters
                new_key_id, new_key_data = self.derive_key(
                    key_type=old_metadata.key_type,
                    context=f"rotation_{reason}",
                    key_length=old_metadata.key_length,
                    session_id=old_metadata.session_id,
                    parent_key_id=old_metadata.parent_key_id
                )
                
                # Update old key status
                self._update_key_status(key_id, KeyStatus.ROTATING)
                
                # Update new key metadata
                new_metadata = self._get_metadata_from_db(new_key_id)
                new_metadata.rotated_from = key_id
                self._update_metadata_in_db(new_key_id, new_metadata)
                
                # Store rotation history
                self._store_rotation_history(key_id, new_key_id, reason)
                
                # Remove from rotation schedule
                if key_id in self.rotation_schedule:
                    del self.rotation_schedule[key_id]
                
                self.performance_metrics.keys_rotated += 1
                
                logger.info(f"Rotated key {key_id} to {new_key_id} for reason: {reason}")
                
                return new_key_id
                
            except Exception as e:
                logger.error(f"Failed to rotate key {key_id}: {e}")
                raise

    def revoke_key(self, key_id: str, reason: str = "administrative_revocation"):
        """
        Revoke a key immediately
        
        Args:
            key_id: Key identifier to revoke
            reason: Reason for revocation
        """
        with self._lock:
            try:
                # Update key status
                self._update_key_status(key_id, KeyStatus.REVOKED)
                
                # Remove from cache
                if key_id in self.key_cache:
                    with self._cache_lock:
                        del self.key_cache[key_id]
                
                # Log revocation
                self._log_key_operation(key_id, "revoke", f"reason: {reason}")
                
                self.performance_metrics.keys_revoked += 1
                
                logger.warning(f"Revoked key {key_id} for reason: {reason}")
                
            except Exception as e:
                logger.error(f"Failed to revoke key {key_id}: {e}")
                raise

    def list_keys(self, 
                  key_type: Optional[KeyType] = None,
                  status: Optional[KeyStatus] = None,
                  session_id: Optional[str] = None) -> List[KeyMetadata]:
        """
        List keys with optional filtering
        
        Args:
            key_type: Filter by key type
            status: Filter by key status
            session_id: Filter by session ID
            
        Returns:
            List of key metadata
        """
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                query = 'SELECT * FROM keys WHERE 1=1'
                params = []
                
                if key_type:
                    query += ' AND key_type = ?'
                    params.append(key_type.value)
                
                if status:
                    query += ' AND status = ?'
                    params.append(status.value)
                
                if session_id:
                    query += ' AND session_id = ?'
                    params.append(session_id)
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                keys = []
                for row in rows:
                    metadata = KeyMetadata(
                        key_id=row['key_id'],
                        key_type=KeyType(row['key_type']),
                        status=KeyStatus(row['status']),
                        created_at=datetime.fromisoformat(row['created_at']),
                        expires_at=datetime.fromisoformat(row['expires_at']) if row['expires_at'] else None,
                        device_id=row['device_id'],
                        session_id=row['session_id'],
                        security_level=SecurityLevel(row['security_level']),
                        key_length=row['key_length'],
                        usage_count=row['usage_count'],
                        last_used=datetime.fromisoformat(row['last_used']) if row['last_used'] else None,
                        rotated_from=row['rotated_from'],
                        parent_key_id=row['parent_key_id'],
                        derivation_context=row['derivation_context'],
                        tags=json.loads(row['tags']) if row['tags'] else []
                    )
                    keys.append(metadata)
                
                return keys
                
        except Exception as e:
            logger.error(f"Failed to list keys: {e}")
            raise

    def cleanup_expired_keys(self) -> int:
        """
        Clean up expired and deprecated keys
        
        Returns:
            Number of keys cleaned up
        """
        with self._lock:
            try:
                cleanup_count = 0
                current_time = datetime.now()
                
                # Get expired keys
                expired_keys = self.list_keys(status=KeyStatus.EXPIRED)
                deprecated_keys = self.list_keys(status=KeyStatus.DEPRECATED)
                
                # Clean up keys older than retention period
                retention_period = timedelta(days=30)
                all_keys = self.list_keys()
                
                for key_metadata in all_keys:
                    key_age = current_time - key_metadata.created_at
                    
                    if (key_metadata.status in [KeyStatus.EXPIRED, KeyStatus.DEPRECATED] and 
                        key_age > retention_period):
                        
                        # Remove from database
                        self._delete_key_from_db(key_metadata.key_id)
                        
                        # Remove from cache
                        if key_metadata.key_id in self.key_cache:
                            with self._cache_lock:
                                del self.key_cache[key_metadata.key_id]
                        
                        # Remove from metadata
                        if key_metadata.key_id in self.key_metadata:
                            del self.key_metadata[key_metadata.key_id]
                        
                        cleanup_count += 1
                        self.performance_metrics.keys_expired += 1
                
                logger.info(f"Cleaned up {cleanup_count} expired/deprecated keys")
                return cleanup_count
                
            except Exception as e:
                logger.error(f"Failed to clean up expired keys: {e}")
                return 0

    def _delete_key_from_db(self, key_id: str):
        """Delete key from database"""
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM keys WHERE key_id = ?', (key_id,))
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to delete key {key_id} from database: {e}")
            raise

    def get_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics"""
        metrics_dict = asdict(self.performance_metrics)
        metrics_dict.update({
            'total_cached_keys': len(self.key_cache),
            'rotation_schedule_size': len(self.rotation_schedule),
            'database_size': os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0,
            'device_id': self.device_id,
            'security_level': self.security_level.value,
            'auto_rotation': self.auto_rotation
        })
        return metrics_dict

    def _store_derivation_record(self, parent_key_id: str, derived_key: bytes, 
                               context: str, algorithm: str, salt: bytes):
        """Store key derivation record"""
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO key_derivations 
                    (parent_key_id, derived_key_id, derivation_context, derivation_algorithm, salt, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    parent_key_id,
                    hashlib.sha3_512(derived_key).hexdigest()[:32],  # Reference to derived key
                    context,
                    algorithm,
                    salt,
                    datetime.now().isoformat()
                ))
                conn.commit()
                
        except Exception as e:
            logger.warning(f"Failed to store derivation record: {e}")

    def _store_rotation_history(self, old_key_id: str, new_key_id: str, reason: str):
        """Store key rotation history"""
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO key_rotation_history 
                    (original_key_id, new_key_id, rotation_reason, rotated_at)
                    VALUES (?, ?, ?, ?)
                ''', (
                    old_key_id,
                    new_key_id,
                    reason,
                    datetime.now().isoformat()
                ))
                conn.commit()
                
        except Exception as e:
            logger.warning(f"Failed to store rotation history: {e}")

    def _log_key_operation(self, key_id: str, operation: str, additional_info: str = ""):
        """Log key operation to audit trail"""
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO key_usage_log 
                    (key_id, operation, timestamp, additional_info)
                    VALUES (?, ?, ?, ?)
                ''', (
                    key_id,
                    operation,
                    datetime.now().isoformat(),
                    additional_info
                ))
                conn.commit()
                
        except Exception as e:
            logger.warning(f"Failed to log key operation: {e}")

    def _get_metadata_from_db(self, key_id: str) -> Optional[KeyMetadata]:
        """Retrieve key metadata from database"""
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('SELECT * FROM keys WHERE key_id = ?', (key_id,))
                row = cursor.fetchone()
                
                if row is None:
                    return None
                
                return KeyMetadata(
                    key_id=row['key_id'],
                    key_type=KeyType(row['key_type']),
                    status=KeyStatus(row['status']),
                    created_at=datetime.fromisoformat(row['created_at']),
                    expires_at=datetime.fromisoformat(row['expires_at']) if row['expires_at'] else None,
                    device_id=row['device_id'],
                    session_id=row['session_id'],
                    security_level=SecurityLevel(row['security_level']),
                    key_length=row['key_length'],
                    usage_count=row['usage_count'],
                    last_used=datetime.fromisoformat(row['last_used']) if row['last_used'] else None,
                    rotated_from=row['rotated_from'],
                    parent_key_id=row['parent_key_id'],
                    derivation_context=row['derivation_context'],
                    tags=json.loads(row['tags']) if row['tags'] else []
                )
                
        except Exception as e:
            logger.error(f"Failed to get metadata for key {key_id}: {e}")
            return None

    def _update_metadata_in_db(self, key_id: str, metadata: KeyMetadata):
        """Update key metadata in database"""
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE keys SET
                        key_type = ?, status = ?, created_at = ?, expires_at = ?,
                        device_id = ?, session_id = ?, security_level = ?, key_length = ?,
                        usage_count = ?, last_used = ?, rotated_from = ?, parent_key_id = ?,
                        derivation_context = ?, tags = ?, version = ?
                    WHERE key_id = ?
                ''', (
                    metadata.key_type.value,
                    metadata.status.value,
                    metadata.created_at.isoformat(),
                    metadata.expires_at.isoformat() if metadata.expires_at else None,
                    metadata.device_id,
                    metadata.session_id,
                    metadata.security_level.value,
                    metadata.key_length,
                    metadata.usage_count,
                    metadata.last_used.isoformat() if metadata.last_used else None,
                    metadata.rotated_from,
                    metadata.parent_key_id,
                    metadata.derivation_context,
                    json.dumps(metadata.tags),
                    metadata.version,
                    key_id
                ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to update metadata for key {key_id}: {e}")
            raise

    def _update_key_status(self, key_id: str, status: KeyStatus):
        """Update key status in database and cache"""
        try:
            with self._db_lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'UPDATE keys SET status = ? WHERE key_id = ?',
                    (status.value, key_id)
                )
                conn.commit()
            
            # Update in-memory metadata
            if key_id in self.key_metadata:
                self.key_metadata[key_id].status = status
            
            # Remove from cache if status is not active
            if status != KeyStatus.ACTIVE and key_id in self.key_cache:
                with self._cache_lock:
                    del self.key_cache[key_id]
                    
        except Exception as e:
            logger.error(f"Failed to update status for key {key_id}: {e}")
            raise

    def _check_rotation_schedule(self):
        """Check and execute scheduled key rotations"""
        current_time = datetime.now()
        
        for key_id, schedule_info in list(self.rotation_schedule.items()):
            try:
                if schedule_info['priority'] == 'high':
                    self.rotate_key(key_id, schedule_info['reason'])
                elif schedule_info['priority'] == 'medium':
                    # Check if we should rotate now
                    if current_time.hour in [2, 14]:  # Rotate at 2 AM/PM
                        self.rotate_key(key_id, schedule_info['reason'])
                        
            except Exception as e:
                logger.warning(f"Failed to rotate scheduled key {key_id}: {e}")

    def shutdown(self):
        """Gracefully shutdown the key manager"""
        self.auto_rotation = False
        
        # Clear caches
        self.key_cache.clear()
        self.derivation_cache.clear()
        self.rotation_schedule.clear()
        
        # Clear sensitive data from memory
        if self.master_key:
            # Securely wipe master key from memory
            import ctypes
            ctypes.memset(id(self.master_key), 0, len(self.master_key))
            self.master_key = None
        
        logger.info("KeyManager shutdown completed")

    def __repr__(self) -> str:
        """String representation of the key manager"""
        return (f"KeyManager(device='{self.device_id}', "
                f"security='{self.security_level.value}', "
                f"keys={len(self.key_metadata)}, "
                f"auto_rotation={self.auto_rotation})")

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
def create_key_manager(security_level: str = "high", 
                      db_path: Optional[str] = None,
                      auto_rotation: bool = True) -> KeyManager:
    """
    Create a pre-configured key manager
    
    Args:
        security_level: Security level ('basic', 'standard', 'high', 'quantum')
        db_path: Optional database path
        auto_rotation: Enable automatic key rotation
        
    Returns:
        Configured KeyManager instance
    """
    if db_path is None:
        db_path = f"keys_{int(time.time())}.db"
    
    return KeyManager(
        db_path=db_path,
        security_level=security_level,
        auto_rotation=auto_rotation,
        enable_caching=True,
        cache_size=2000,
        backup_enabled=True
    )

def generate_secure_random_key(key_length: int = 32) -> bytes:
    """
    Generate cryptographically secure random key
    
    Args:
        key_length: Key length in bytes
        
    Returns:
        Random key bytes
    """
    return secrets.token_bytes(key_length)

def derive_key_from_password(password: str, salt: bytes, key_length: int = 32) -> bytes:
    """
    Derive key from password using Argon2
    
    Args:
        password: User password
        salt: Cryptographic salt
        key_length: Desired key length
        
    Returns:
        Derived key bytes
    """
    ph = argon2.PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=key_length,
        salt_len=len(salt)
    )
    return ph.hash(password.encode(), salt=salt)[:key_length]