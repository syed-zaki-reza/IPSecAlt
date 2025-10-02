"""
ai_logic.py
AI-Generated Logic for Dynamic Cryptographic Operations

This module implements neural network-based generation of cryptographic logic
for the tensor-based post-quantum cryptographic system. It creates dynamic,
unpredictable transformation patterns that enhance security against both
classical and quantum attacks.
"""

import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, Model
import hashlib
import hmac
import pickle
import json
import logging
import time
from datetime import datetime
from typing import Tuple, Optional, Dict, Any, List
from sklearn.metrics import mutual_info_score
import warnings

# Suppress TensorFlow warnings for cleaner output
warnings.filterwarnings('ignore', category=FutureWarning)
tf.get_logger().setLevel('ERROR')


class AILogicGenerator:
    """
    AI-based logic generator for dynamic cryptographic transformations
    
    Uses deep neural networks to generate session-specific cryptographic
    logic that is deterministic for the same inputs but unpredictable
    and high-entropy for different sessions.
    """
    
    def __init__(self, input_dim: int = 64, output_dim: int = 64,
                 architecture: str = 'standard', training_mode: bool = True):
        """
        Initialize AI logic generator
        
        Args:
            input_dim: Dimension of input seed vector
            output_dim: Dimension of output logic vector
            architecture: Model architecture ('basic', 'standard', 'advanced')
            training_mode: Whether to enable training capabilities
        """
        self.input_dim = input_dim
        self.output_dim = output_dim
        self.architecture = architecture
        self.training_mode = training_mode
        
        # Initialize logging
        self.logger = logging.getLogger(__name__)
        
        # Model and training components
        self.model = None
        self.training_history = []
        self.generation_cache = {}
        self.performance_metrics = {
            'generations': 0,
            'cache_hits': 0,
            'average_generation_time': 0.0,
            'entropy_scores': []
        }
        
        # Build the neural network model
        self._build_model()
        
        # Initialize training data if in training mode
        if self.training_mode:
            self._initialize_training_components()
        
        self.logger.info(f"AI Logic Generator initialized: {self.architecture} architecture, "
                        f"input_dim={input_dim}, output_dim={output_dim}")
    
    def _build_model(self):
        """Build neural network model based on architecture specification"""
        architecture_configs = {
            'basic': {
                'hidden_layers': [128, 64],
                'dropout_rates': [0.1, 0.1],
                'activations': ['relu', 'tanh'],
                'use_batch_norm': False,
                'complexity_factor': 1
            },
            'standard': {
                'hidden_layers': [256, 128, 64],
                'dropout_rates': [0.2, 0.2, 0.1],
                'activations': ['relu', 'tanh', 'sigmoid'],
                'use_batch_norm': True,
                'complexity_factor': 2
            },
            'advanced': {
                'hidden_layers': [512, 256, 128, 64],
                'dropout_rates': [0.3, 0.25, 0.2, 0.1],
                'activations': ['relu', 'elu', 'tanh', 'sigmoid'],
                'use_batch_norm': True,
                'complexity_factor': 3
            }
        }
        
        config = architecture_configs.get(self.architecture, architecture_configs['standard'])
        
        # Build model layers
        inputs = keras.Input(shape=(self.input_dim,), name='session_seed_input')
        x = inputs
        
        # Hidden layers
        for i, (units, dropout, activation) in enumerate(zip(
            config['hidden_layers'], 
            config['dropout_rates'], 
            config['activations']
        )):
            layer_name = f'{activation}_layer_{i+1}'
            x = layers.Dense(units, activation=activation, name=layer_name)(x)
            
            if config['use_batch_norm']:
                x = layers.BatchNormalization(name=f'batch_norm_{i+1}')(x)
            
            if dropout > 0:
                x = layers.Dropout(dropout, name=f'dropout_{i+1}')(x)
        
        # Bottleneck layer for additional complexity
        bottleneck_size = max(32, self.output_dim // 2)
        x = layers.Dense(bottleneck_size, activation='tanh', name='bottleneck')(x)
        
        # Output layer with no activation for maximum range
        outputs = layers.Dense(self.output_dim, activation='linear', name='logic_output')(x)
        
        # Create model
        self.model = keras.Model(inputs=inputs, outputs=outputs, name=f'ai_logic_{self.architecture}')
        
        # Compile with custom loss function
        self.model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss=self._cryptographic_loss,
            metrics=[self._entropy_metric, 'mse']
        )
        
        self.logger.debug(f"Model built with {self.model.count_params():,} parameters")
    
    def _cryptographic_loss(self, y_true, y_pred):
        """
        Custom loss function optimized for cryptographic properties
        
        Combines standard MSE with terms that encourage:
        - High entropy (diverse outputs)
        - Low correlation between different inputs
        - Balanced value distribution
        """
        # Standard reconstruction loss
        mse_loss = tf.reduce_mean(tf.square(y_true - y_pred))
        
        # Entropy regularization - encourage diverse outputs
        # Approximate entropy using histogram
        y_pred_clipped = tf.clip_by_value(y_pred, -10, 10)
        hist_bins = 20
        hist_range = [-10, 10]
        
        # Create histogram (approximation)
        hist = tf.histogram_fixed_width(y_pred_clipped, hist_range, nbins=hist_bins)
        hist_normalized = hist / tf.reduce_sum(hist)
        hist_normalized = tf.maximum(hist_normalized, 1e-10)  # Avoid log(0)
        
        entropy = -tf.reduce_sum(hist_normalized * tf.math.log(hist_normalized))
        entropy_loss = -0.01 * entropy  # Negative because we want to maximize entropy
        
        # Variance regularization - encourage spread in values
        variance = tf.math.reduce_variance(y_pred, axis=1)
        variance_loss = -0.005 * tf.reduce_mean(variance)  # Encourage high variance
        
        # Correlation penalty - discourage patterns within output
        y_pred_centered = y_pred - tf.reduce_mean(y_pred, axis=1, keepdims=True)
        correlation_matrix = tf.linalg.matmul(y_pred_centered, y_pred_centered, transpose_b=True)
        correlation_loss = 0.001 * tf.reduce_mean(tf.square(correlation_matrix))
        
        total_loss = mse_loss + entropy_loss + variance_loss + correlation_loss
        return total_loss
    
    def _entropy_metric(self, y_true, y_pred):
        """Metric to monitor entropy of generated outputs"""
        y_pred_clipped = tf.clip_by_value(y_pred, -10, 10)
        variance = tf.math.reduce_variance(y_pred_clipped, axis=1)
        return tf.reduce_mean(variance)
    
    def _initialize_training_components(self):
        """Initialize components needed for training"""
        self.training_callbacks = [
            keras.callbacks.EarlyStopping(
                monitor='val_loss', 
                patience=15, 
                restore_best_weights=True,
                verbose=0
            ),
            keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=8,
                min_lr=1e-6,
                verbose=0
            )
        ]
        
        # Generate initial training data
        self._generate_initial_training_data()
    
    def _generate_initial_training_data(self, num_samples: int = 2000):
        """Generate initial training data for the model"""
        self.logger.info(f"Generating {num_samples} initial training samples...")
        
        X_train = []
        y_train = []
        
        for i in range(num_samples):
            # Create diverse session parameters
            session_id = f"training_session_{i}_{int(time.time())}"
            device_fp = f"device_{np.random.randint(100000, 999999):06d}"
            timestamp = time.time() + np.random.uniform(-86400*30, 86400*30)  # ±30 days
            
            # Generate input seed
            seed = self._create_session_seed(session_id, device_fp, timestamp)
            X_train.append(seed)
            
            # Generate target output with desired cryptographic properties
            target = self._generate_cryptographic_target(seed, i)
            y_train.append(target)
        
        self.X_train = np.array(X_train)
        self.y_train = np.array(y_train)
        
        self.logger.info(f"Training data generated: X shape {self.X_train.shape}, y shape {self.y_train.shape}")
    
    def _generate_cryptographic_target(self, seed: np.ndarray, index: int) -> np.ndarray:
        """Generate target output with good cryptographic properties"""
        # Use seed to create deterministic but complex target
        seed_hash = hashlib.sha256(seed.tobytes() + str(index).encode()).digest()
        
        # Convert hash to float array
        hash_array = np.frombuffer(seed_hash, dtype=np.uint8)
        
        # Extend to output dimension
        extended = np.tile(hash_array, (self.output_dim // len(hash_array)) + 1)[:self.output_dim]
        
        # Normalize and apply transformations
        target = (extended.astype(np.float32) - 128) / 128.0
        
        # Apply nonlinear transformations for complexity
        target = np.tanh(target * 2)
        target = np.sin(target * np.pi) * np.cos(target * np.pi / 2)
        
        # Ensure good distribution properties
        target = target / np.std(target) if np.std(target) > 0 else target
        target = np.clip(target, -3, 3)
        
        return target
    
    def _create_session_seed(self, session_id: str, device_fingerprint: str, 
                           timestamp: Optional[float] = None) -> np.ndarray:
        """
        Create deterministic seed from session parameters
        
        Args:
            session_id: Unique session identifier
            device_fingerprint: Device-specific fingerprint
            timestamp: Optional timestamp (uses current time if None)
            
        Returns:
            Normalized seed vector for neural network input
        """
        if timestamp is None:
            timestamp = time.time()
        
        # Combine session information
        combined_data = f"{session_id}_{device_fingerprint}_{timestamp:.6f}"
        
        # Create multiple hash values for diversity
        sha256_hash = hashlib.sha256(combined_data.encode()).digest()
        sha1_hash = hashlib.sha1(combined_data.encode()).digest()
        md5_hash = hashlib.md5(combined_data.encode()).digest()
        
        # HMAC with session ID as key for additional security
        hmac_hash = hmac.new(
            session_id.encode()[:32].ljust(32, b'\0'), 
            combined_data.encode(), 
            hashlib.sha256
        ).digest()
        
        # Combine all hashes
        combined_hash = sha256_hash + sha1_hash + md5_hash + hmac_hash
        
        # Convert to seed vector
        seed_bytes = np.frombuffer(combined_hash, dtype=np.uint8)[:self.input_dim]
        
        # Pad if necessary
        if len(seed_bytes) < self.input_dim:
            padding = np.random.RandomState(42).randint(0, 256, 
                                                       self.input_dim - len(seed_bytes), 
                                                       dtype=np.uint8)
            seed_bytes = np.concatenate([seed_bytes, padding])
        
        # Normalize to [-1, 1] range for neural network
        normalized_seed = (seed_bytes.astype(np.float32) - 128) / 128.0
        
        return normalized_seed
    
    def generate_session_logic(self, session_id: str, device_fingerprint: str,
                              timestamp: Optional[float] = None,
                              use_cache: bool = True) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Generate AI-based cryptographic logic for a session
        
        Args:
            session_id: Unique session identifier
            device_fingerprint: Device-specific fingerprint
            timestamp: Optional timestamp for deterministic generation
            use_cache: Whether to use caching for repeated requests
            
        Returns:
            Tuple of (logic_vector, metadata)
        """
        # Create cache key
        cache_key = f"{session_id}_{device_fingerprint}_{timestamp}"
        
        # Check cache first
        if use_cache and cache_key in self.generation_cache:
            self.performance_metrics['cache_hits'] += 1
            cached_result = self.generation_cache[cache_key]
            return cached_result['logic_vector'], cached_result['metadata']
        
        start_time = time.time()
        
        # Create input seed
        seed = self._create_session_seed(session_id, device_fingerprint, timestamp)
        
        # Generate logic using trained model
        logic_vector = self.model.predict(seed.reshape(1, -1), verbose=0)[0]
        
        # Post-process for enhanced cryptographic properties
        processed_logic = self._post_process_logic(logic_vector)
        
        # Calculate metadata
        generation_time = time.time() - start_time
        entropy_score = self._calculate_entropy(processed_logic)
        
        metadata = {
            'session_id': session_id,
            'device_fingerprint': device_fingerprint,
            'timestamp': timestamp or time.time(),
            'generation_time': generation_time,
            'entropy_score': entropy_score,
            'logic_vector_hash': hashlib.sha256(processed_logic.tobytes()).hexdigest(),
            'model_architecture': self.architecture,
            'seed_hash': hashlib.sha256(seed.tobytes()).hexdigest()
        }
        
        # Update performance metrics
        self.performance_metrics['generations'] += 1
        self.performance_metrics['entropy_scores'].append(entropy_score)
        
        # Update average generation time
        total_time = (self.performance_metrics['average_generation_time'] * 
                     (self.performance_metrics['generations'] - 1) + generation_time)
        self.performance_metrics['average_generation_time'] = total_time / self.performance_metrics['generations']
        
        # Cache result
        if use_cache:
            self.generation_cache[cache_key] = {
                'logic_vector': processed_logic.copy(),
                'metadata': metadata.copy()
            }
        
        self.logger.debug(f"Generated logic for session {session_id[:16]}... "
                         f"(entropy: {entropy_score:.3f}, time: {generation_time:.4f}s)")
        
        return processed_logic, metadata
    
    def _post_process_logic(self, raw_logic: np.ndarray) -> np.ndarray:
        """
        Post-process raw neural network output for cryptographic use
        
        Args:
            raw_logic: Raw output from neural network
            
        Returns:
            Post-processed logic vector optimized for cryptography
        """
        # Apply multiple nonlinear transformations
        processed = raw_logic.copy()
        
        # Layer 1: Tanh activation for bounded output
        processed = np.tanh(processed * 2)
        
        # Layer 2: Sinusoidal transformation for additional nonlinearity  
        processed = np.sin(processed * np.pi) * np.cos(processed * np.pi / 3)
        
        # Layer 3: Bit-level transformations
        # Convert to integer representation for XOR operations
        processed = (processed * 127).astype(np.int8)
        
        # Layer 4: Ensure non-zero values (avoid weak encryption)
        zero_mask = processed == 0
        processed[zero_mask] = np.random.choice([-1, 1], size=np.sum(zero_mask))
        
        # Layer 5: Enhance entropy through permutation
        perm_seed = np.sum(np.abs(processed)) % 1000
        np.random.seed(perm_seed)
        perm_indices = np.random.permutation(len(processed))
        processed = processed[perm_indices]
        
        return processed
    
    def _calculate_entropy(self, data: np.ndarray) -> float:
        """Calculate approximate entropy of data array"""
        # Convert to histogram
        hist, _ = np.histogram(data, bins=min(20, len(np.unique(data))))
        hist = hist + 1e-10  # Avoid log(0)
        
        # Calculate probabilities
        probabilities = hist / np.sum(hist)
        
        # Calculate entropy
        entropy = -np.sum(probabilities * np.log2(probabilities))
        
        return float(entropy)
    
    def train_model(self, epochs: int = 100, validation_split: float = 0.2,
                   batch_size: int = 32, verbose: int = 1) -> keras.callbacks.History:
        """
        Train the AI logic generation model
        
        Args:
            epochs: Number of training epochs
            validation_split: Fraction of data for validation
            batch_size: Training batch size
            verbose: Verbosity level
            
        Returns:
            Training history
        """
        if not self.training_mode:
            raise ValueError("Training mode not enabled")
        
        self.logger.info(f"Starting model training for {epochs} epochs...")
        
        # Train model
        history = self.model.fit(
            self.X_train, self.y_train,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split,
            callbacks=self.training_callbacks,
            verbose=verbose
        )
        
        self.training_history.append(history)
        self.logger.info("Model training completed")
        
        return history
    
    def evaluate_logic_quality(self, num_samples: int = 100) -> Dict[str, Any]:
        """
        Evaluate the quality of generated logic vectors
        
        Args:
            num_samples: Number of samples to generate for evaluation
            
        Returns:
            Quality metrics dictionary
        """
        self.logger.info(f"Evaluating logic quality with {num_samples} samples...")
        
        logic_samples = []
        entropy_scores = []
        correlations = []
        generation_times = []
        
        # Generate samples
        for i in range(num_samples):
            session_id = f"eval_session_{i}"
            device_fp = f"eval_device_{i}"
            
            start_time = time.time()
            logic_vector, metadata = self.generate_session_logic(
                session_id, device_fp, use_cache=False
            )
            generation_time = time.time() - start_time
            
            logic_samples.append(logic_vector)
            entropy_scores.append(metadata['entropy_score'])
            generation_times.append(generation_time)
        
        # Calculate inter-sample correlations
        logic_matrix = np.array(logic_samples)
        for i in range(min(50, num_samples-1)):
            for j in range(i+1, min(50, num_samples)):
                corr = np.corrcoef(logic_matrix[i], logic_matrix[j])[0, 1]
                if not np.isnan(corr):
                    correlations.append(abs(corr))
        
        # Calculate uniqueness
        unique_vectors = len(set(tuple(v.tolist()) for v in logic_matrix))
        uniqueness_ratio = unique_vectors / num_samples
        
        # Statistical analysis
        quality_metrics = {
            'num_samples': num_samples,
            'entropy': {
                'mean': float(np.mean(entropy_scores)),
                'std': float(np.std(entropy_scores)),
                'min': float(np.min(entropy_scores)),
                'max': float(np.max(entropy_scores))
            },
            'correlations': {
                'mean': float(np.mean(correlations)) if correlations else 0.0,
                'std': float(np.std(correlations)) if correlations else 0.0,
                'max': float(np.max(correlations)) if correlations else 0.0
            },
            'uniqueness_ratio': uniqueness_ratio,
            'generation_time': {
                'mean': float(np.mean(generation_times)),
                'std': float(np.std(generation_times))
            },
            'quality_assessment': {
                'entropy_good': np.mean(entropy_scores) > 3.0,
                'correlation_good': (np.mean(correlations) if correlations else 0) < 0.1,
                'uniqueness_good': uniqueness_ratio > 0.95,
                'performance_good': np.mean(generation_times) < 0.1
            }
        }
        
        self.logger.info(f"Logic quality evaluation completed. "
                        f"Mean entropy: {quality_metrics['entropy']['mean']:.3f}, "
                        f"Mean correlation: {quality_metrics['correlations']['mean']:.4f}, "
                        f"Uniqueness: {uniqueness_ratio:.3f}")
        
        return quality_metrics
    
    def save_model(self, filepath: str, include_training_data: bool = False):
        """Save the AI logic model and metadata"""
        # Save the model
        model_path = f"{filepath}_model.h5"
        self.model.save(model_path)
        
        # Save metadata
        metadata = {
            'input_dim': self.input_dim,
            'output_dim': self.output_dim,
            'architecture': self.architecture,
            'performance_metrics': self.performance_metrics,
            'training_mode': self.training_mode
        }
        
        if include_training_data and self.training_mode:
            metadata['training_data'] = {
                'X_train': self.X_train.tolist(),
                'y_train': self.y_train.tolist()
            }
        
        metadata_path = f"{filepath}_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        self.logger.info(f"Model saved to {model_path}, metadata to {metadata_path}")
    
    def load_model(self, filepath: str):
        """Load a previously saved AI logic model"""
        model_path = f"{filepath}_model.h5"
        metadata_path = f"{filepath}_metadata.json"
        
        # Load model
        self.model = keras.models.load_model(
            model_path,
            custom_objects={
                '_cryptographic_loss': self._cryptographic_loss,
                '_entropy_metric': self._entropy_metric
            }
        )
        
        # Load metadata
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        self.input_dim = metadata['input_dim']
        self.output_dim = metadata['output_dim']
        self.architecture = metadata['architecture']
        self.performance_metrics = metadata['performance_metrics']
        self.training_mode = metadata['training_mode']
        
        # Load training data if available
        if 'training_data' in metadata and self.training_mode:
            self.X_train = np.array(metadata['training_data']['X_train'])
            self.y_train = np.array(metadata['training_data']['y_train'])
        
        self.logger.info(f"Model loaded from {model_path}")
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics"""
        return self.performance_metrics.copy()
    
    def clear_cache(self):
        """Clear the generation cache"""
        cache_size = len(self.generation_cache)
        self.generation_cache.clear()
        self.logger.info(f"Cleared cache ({cache_size} entries)")
    
    def benchmark_performance(self, num_iterations: int = 1000) -> Dict[str, float]:
        """Benchmark logic generation performance"""
        self.logger.info(f"Benchmarking performance with {num_iterations} iterations...")
        
        start_time = time.time()
        
        for i in range(num_iterations):
            session_id = f"benchmark_session_{i}"
            device_fp = f"benchmark_device_{i}"
            logic_vector, _ = self.generate_session_logic(session_id, device_fp, use_cache=False)
        
        total_time = time.time() - start_time
        
        results = {
            'total_time': total_time,
            'iterations': num_iterations,
            'ops_per_second': num_iterations / total_time,
            'time_per_op_ms': (total_time / num_iterations) * 1000,
            'average_entropy': np.mean(self.performance_metrics['entropy_scores'][-num_iterations:]) if self.performance_metrics['entropy_scores'] else 0
        }
        
        self.logger.info(f"Benchmark completed: {results['ops_per_second']:.1f} ops/sec, "
                        f"{results['time_per_op_ms']:.3f} ms/op")
        
        return results
    
    def __repr__(self) -> str:
        """String representation of the AI logic generator"""
        return (f"AILogicGenerator(arch='{self.architecture}', "
                f"input_dim={self.input_dim}, output_dim={self.output_dim}, "
                f"generations={self.performance_metrics['generations']})")
