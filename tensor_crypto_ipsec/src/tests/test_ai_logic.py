"""
test_ai_logic.py
Comprehensive test suite for the AI logic generator

Tests cover:
- Model architecture and initialization
- Session logic generation and determinism
- Cryptographic quality and entropy
- Performance and caching
- Training and model persistence
- Integration scenarios
"""

import unittest
import numpy as np
import tensorflow as tf
import hashlib
import os
import tempfile
import time
import json
from unittest.mock import patch, MagicMock
import warnings

# Suppress TensorFlow warnings during testing
warnings.filterwarnings('ignore')
tf.get_logger().setLevel('ERROR')

# Import the module to test
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from ai_logic import AILogicGenerator


class TestAILogicGenerator(unittest.TestCase):
    """Test suite for AILogicGenerator class"""
    
    def setUp(self):
        """Set up test environment before each test"""
        self.generator = AILogicGenerator(
            input_dim=32,
            output_dim=16,
            architecture='basic',
            training_mode=False  # Disable training for faster testing
        )
        self.session_id = "test_session_123"
        self.device_fingerprint = "test_device_abc"
    
    def tearDown(self):
        """Clean up after each test"""
        # Clear caches and reset state
        self.generator.clear_cache()
    
    def test_initialization(self):
        """Test generator initialization"""
        self.assertEqual(self.generator.input_dim, 32)
        self.assertEqual(self.generator.output_dim, 16)
        self.assertEqual(self.generator.architecture, 'basic')
        self.assertFalse(self.generator.training_mode)
        self.assertIsNotNone(self.generator.model)
        
        # Check model structure
        self.assertEqual(len(self.generator.model.inputs), 1)
        self.assertEqual(len(self.generator.model.outputs), 1)
        self.assertEqual(self.generator.model.input_shape, (None, 32))
        self.assertEqual(self.generator.model.output_shape, (None, 16))
    
    def test_different_architectures(self):
        """Test different model architectures"""
        architectures = ['basic', 'standard', 'advanced']
        
        for arch in architectures:
            with self.subTest(architecture=arch):
                gen = AILogicGenerator(
                    input_dim=64,
                    output_dim=32,
                    architecture=arch,
                    training_mode=False
                )
                
                # Check model is built
                self.assertIsNotNone(gen.model)
                self.assertEqual(gen.architecture, arch)
                
                # Advanced should have more parameters than basic
                if arch == 'advanced':
                    basic_gen = AILogicGenerator(architecture='basic', training_mode=False)
                    self.assertGreater(gen.model.count_params(), basic_gen.model.count_params())
    
    def test_session_seed_generation(self):
        """Test session seed creation"""
        seed1 = self.generator._create_session_seed(
            self.session_id, self.device_fingerprint, 1234567890.0
        )
        
        # Check seed properties
        self.assertEqual(len(seed1), self.generator.input_dim)
        self.assertEqual(seed1.dtype, np.float32)
        self.assertTrue(np.all(seed1 >= -1.0))
        self.assertTrue(np.all(seed1 <= 1.0))
        
        # Same parameters should generate same seed (deterministic)
        seed2 = self.generator._create_session_seed(
            self.session_id, self.device_fingerprint, 1234567890.0
        )
        self.assertTrue(np.array_equal(seed1, seed2))
        
        # Different parameters should generate different seeds
        seed3 = self.generator._create_session_seed(
            "different_session", self.device_fingerprint, 1234567890.0
        )
        self.assertFalse(np.array_equal(seed1, seed3))
        
        seed4 = self.generator._create_session_seed(
            self.session_id, "different_device", 1234567890.0
        )
        self.assertFalse(np.array_equal(seed1, seed4))
        
        seed5 = self.generator._create_session_seed(
            self.session_id, self.device_fingerprint, 9876543210.0
        )
        self.assertFalse(np.array_equal(seed1, seed5))
    
    def test_basic_logic_generation(self):
        """Test basic logic generation"""
        logic_vector, metadata = self.generator.generate_session_logic(
            self.session_id, self.device_fingerprint
        )
        
        # Check logic vector properties
        self.assertEqual(len(logic_vector), self.generator.output_dim)
        self.assertEqual(logic_vector.dtype, np.int8)
        self.assertTrue(np.all(logic_vector >= -128))
        self.assertTrue(np.all(logic_vector <= 127))
        
        # Check metadata
        self.assertIsInstance(metadata, dict)
        self.assertIn('session_id', metadata)
        self.assertIn('device_fingerprint', metadata)
        self.assertIn('timestamp', metadata)
        self.assertIn('generation_time', metadata)
        self.assertIn('entropy_score', metadata)
        self.assertIn('logic_vector_hash', metadata)
        
        self.assertEqual(metadata['session_id'], self.session_id)
        self.assertEqual(metadata['device_fingerprint'], self.device_fingerprint)
        self.assertGreater(metadata['entropy_score'], 0)
        self.assertGreater(metadata['generation_time'], 0)
    
    def test_deterministic_generation(self):
        """Test that generation is deterministic for same inputs"""
        timestamp = 1234567890.0
        
        logic1, metadata1 = self.generator.generate_session_logic(
            self.session_id, self.device_fingerprint, timestamp, use_cache=False
        )
        logic2, metadata2 = self.generator.generate_session_logic(
            self.session_id, self.device_fingerprint, timestamp, use_cache=False
        )
        
        # Same inputs should produce same outputs
        self.assertTrue(np.array_equal(logic1, logic2))
        self.assertEqual(metadata1['logic_vector_hash'], metadata2['logic_vector_hash'])
    
    def test_logic_uniqueness(self):
        """Test that different sessions produce different logic"""
        logic_vectors = []
        
        # Generate logic for different sessions
        for i in range(10):
            session_id = f"unique_session_{i}"
            logic_vector, _ = self.generator.generate_session_logic(
                session_id, self.device_fingerprint, use_cache=False
            )
            logic_vectors.append(tuple(logic_vector.tolist()))
        
        # All logic vectors should be unique
        unique_vectors = set(logic_vectors)
        self.assertEqual(len(unique_vectors), len(logic_vectors))
    
    def test_entropy_calculation(self):
        """Test entropy calculation"""
        # Test with known data
        uniform_data = np.arange(-10, 10, dtype=np.int8)  # Uniform distribution
        low_entropy_data = np.full(20, 5, dtype=np.int8)  # All same value
        
        uniform_entropy = self.generator._calculate_entropy(uniform_data)
        low_entropy = self.generator._calculate_entropy(low_entropy_data)
        
        # Uniform distribution should have higher entropy
        self.assertGreater(uniform_entropy, low_entropy)
        self.assertGreater(uniform_entropy, 3.0)  # Should be reasonably high
        self.assertLess(low_entropy, 1.0)  # Should be low
    
    def test_post_processing(self):
        """Test logic post-processing"""
        # Create test raw logic
        raw_logic = np.random.uniform(-3, 3, self.generator.output_dim)
        
        # Post-process
        processed = self.generator._post_process_logic(raw_logic)
        
        # Check properties
        self.assertEqual(len(processed), self.generator.output_dim)
        self.assertEqual(processed.dtype, np.int8)
        self.assertTrue(np.all(processed >= -128))
        self.assertTrue(np.all(processed <= 127))
        
        # Should not contain all zeros (weak encryption avoidance)
        self.assertFalse(np.all(processed == 0))
        
        # Should be different from input (transformed)
        self.assertFalse(np.array_equal(processed, raw_logic.astype(np.int8)))
    
    def test_caching_mechanism(self):
        """Test logic generation caching"""
        timestamp = time.time()
        
        # First call should generate and cache
        start_time = time.time()
        logic1, metadata1 = self.generator.generate_session_logic(
            self.session_id, self.device_fingerprint, timestamp, use_cache=True
        )
        first_call_time = time.time() - start_time
        
        # Second call should use cache (should be faster)
        start_time = time.time()
        logic2, metadata2 = self.generator.generate_session_logic(
            self.session_id, self.device_fingerprint, timestamp, use_cache=True
        )
        second_call_time = time.time() - start_time
        
        # Results should be identical
        self.assertTrue(np.array_equal(logic1, logic2))
        self.assertEqual(metadata1['logic_vector_hash'], metadata2['logic_vector_hash'])
        
        # Second call should be faster (cached)
        self.assertLess(second_call_time, first_call_time)
        
        # Check cache hit metrics
        initial_cache_hits = self.generator.performance_metrics['cache_hits']
        
        # Call again to increment cache hits
        self.generator.generate_session_logic(
            self.session_id, self.device_fingerprint, timestamp, use_cache=True
        )
        
        self.assertGreater(self.generator.performance_metrics['cache_hits'], initial_cache_hits)
    
    def test_cache_clearing(self):
        """Test cache clearing functionality"""
        # Generate some cached results
        for i in range(3):
            self.generator.generate_session_logic(
                f"session_{i}", self.device_fingerprint, use_cache=True
            )
        
        # Verify cache has entries
        self.assertGreater(len(self.generator.generation_cache), 0)
        
        # Clear cache
        self.generator.clear_cache()
        
        # Verify cache is empty
        self.assertEqual(len(self.generator.generation_cache), 0)
    
    def test_performance_metrics(self):
        """Test performance metrics tracking"""
        initial_metrics = self.generator.get_performance_metrics()
        initial_generations = initial_metrics['generations']
        
        # Generate some logic
        for i in range(5):
            self.generator.generate_session_logic(
                f"metrics_session_{i}", self.device_fingerprint, use_cache=False
            )
        
        # Check metrics updated
        updated_metrics = self.generator.get_performance_metrics()
        
        self.assertEqual(updated_metrics['generations'], initial_generations + 5)
        self.assertGreater(updated_metrics['average_generation_time'], 0)
        self.assertEqual(len(updated_metrics['entropy_scores']), 
                        initial_generations + 5)
    
    def test_quality_evaluation(self):
        """Test logic quality evaluation"""
        # Run quality evaluation with small sample
        quality_metrics = self.generator.evaluate_logic_quality(num_samples=20)
        
        # Check metrics structure
        self.assertIn('num_samples', quality_metrics)
        self.assertIn('entropy', quality_metrics)
        self.assertIn('correlations', quality_metrics)
        self.assertIn('uniqueness_ratio', quality_metrics)
        self.assertIn('generation_time', quality_metrics)
        self.assertIn('quality_assessment', quality_metrics)
        
        # Check values are reasonable
        self.assertEqual(quality_metrics['num_samples'], 20)
        self.assertGreater(quality_metrics['entropy']['mean'], 0)
        self.assertGreaterEqual(quality_metrics['uniqueness_ratio'], 0.9)  # Should be high
        
        # Check quality assessment
        assessment = quality_metrics['quality_assessment']
        self.assertIsInstance(assessment['entropy_good'], bool)
        self.assertIsInstance(assessment['correlation_good'], bool)
        self.assertIsInstance(assessment['uniqueness_good'], bool)
    
    def test_performance_benchmark(self):
        """Test performance benchmarking"""
        # Run small benchmark
        results = self.generator.benchmark_performance(num_iterations=50)
        
        # Check results structure
        self.assertIn('total_time', results)
        self.assertIn('iterations', results)
        self.assertIn('ops_per_second', results)
        self.assertIn('time_per_op_ms', results)
        self.assertIn('average_entropy', results)
        
        # Check values are reasonable
        self.assertEqual(results['iterations'], 50)
        self.assertGreater(results['ops_per_second'], 0)
        self.assertGreater(results['time_per_op_ms'], 0)
        self.assertLess(results['time_per_op_ms'], 1000)  # Should be < 1 second per op
    
    def test_model_save_load(self):
        """Test model saving and loading"""
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, 'test_ai_model')
            
            # Generate some logic to populate metrics
            original_logic, _ = self.generator.generate_session_logic(
                self.session_id, self.device_fingerprint
            )
            
            # Save model
            self.generator.save_model(model_path, include_training_data=False)
            
            # Verify files created
            self.assertTrue(os.path.exists(f"{model_path}_model.h5"))
            self.assertTrue(os.path.exists(f"{model_path}_metadata.json"))
            
            # Create new generator and load model
            new_generator = AILogicGenerator(training_mode=False)
            new_generator.load_model(model_path)
            
            # Verify properties match
            self.assertEqual(new_generator.input_dim, self.generator.input_dim)
            self.assertEqual(new_generator.output_dim, self.generator.output_dim)
            self.assertEqual(new_generator.architecture, self.generator.architecture)
            
            # Generate same logic with loaded model
            loaded_logic, _ = new_generator.generate_session_logic(
                self.session_id, self.device_fingerprint
            )
            
            # Results should be identical
            self.assertTrue(np.array_equal(original_logic, loaded_logic))
    
    def test_cryptographic_loss_function(self):
        """Test the custom cryptographic loss function"""
        # Create test tensors
        y_true = tf.random.normal((32, 16))  # Batch of target vectors
        y_pred = tf.random.normal((32, 16))  # Batch of predicted vectors
        
        # Calculate loss
        loss_value = self.generator._cryptographic_loss(y_true, y_pred)
        
        # Check loss properties
        self.assertIsInstance(loss_value, tf.Tensor)
        self.assertEqual(loss_value.shape, ())  # Scalar
        self.assertGreater(float(loss_value), 0)  # Should be positive
        
        # Test with identical predictions (should have lower loss)
        identical_loss = self.generator._cryptographic_loss(y_true, y_true)
        self.assertLess(float(identical_loss), float(loss_value))
    
    def test_entropy_metric(self):
        """Test the entropy metric function"""
        # Create test data with known properties
        low_variance_data = tf.ones((10, 16)) * 0.5  # Low variance
        high_variance_data = tf.random.uniform((10, 16), -5, 5)  # High variance
        
        low_metric = self.generator._entropy_metric(None, low_variance_data)
        high_metric = self.generator._entropy_metric(None, high_variance_data)
        
        # High variance data should have higher entropy metric
        self.assertGreater(float(high_metric), float(low_metric))
    
    def test_edge_cases(self):
        """Test edge cases and error conditions"""
        # Test with empty session ID
        with self.assertRaises(Exception):
            self.generator.generate_session_logic("", self.device_fingerprint)
        
        # Test with very long session ID
        long_session_id = "x" * 1000
        logic, metadata = self.generator.generate_session_logic(
            long_session_id, self.device_fingerprint
        )
        self.assertEqual(len(logic), self.generator.output_dim)
        
        # Test with special characters in session ID
        special_session_id = "session_!@#$%^&*()_+{}[]|\\:;\"'<>,.?/"
        logic, metadata = self.generator.generate_session_logic(
            special_session_id, self.device_fingerprint
        )
        self.assertEqual(len(logic), self.generator.output_dim)
    
    def test_memory_usage(self):
        """Test that memory usage remains reasonable"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Generate many logic vectors
        for i in range(100):
            self.generator.generate_session_logic(
                f"memory_test_session_{i}", 
                self.device_fingerprint,
                use_cache=False  # Don't cache to avoid memory buildup
            )
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (< 100MB for 100 generations)
        self.assertLess(memory_increase, 100 * 1024 * 1024)
    
    def test_thread_safety(self):
        """Test basic thread safety of generation"""
        import threading
        import queue
        
        results = queue.Queue()
        
        def generate_logic(thread_id):
            try:
                logic, metadata = self.generator.generate_session_logic(
                    f"thread_session_{thread_id}",
                    f"thread_device_{thread_id}",
                    use_cache=False
                )
                results.put(('success', thread_id, logic))
            except Exception as e:
                results.put(('error', thread_id, str(e)))
        
        # Start multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=generate_logic, args=(i,))
            thread.start()
            threads.append(thread)
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Check all threads completed successfully
        success_count = 0
        while not results.empty():
            status, thread_id, result = results.get()
            if status == 'success':
                success_count += 1
                self.assertEqual(len(result), self.generator.output_dim)
            else:
                self.fail(f"Thread {thread_id} failed: {result}")
        
        self.assertEqual(success_count, 5)
    
    def test_string_representation(self):
        """Test string representation"""
        repr_str = repr(self.generator)
        
        self.assertIn('AILogicGenerator', repr_str)
        self.assertIn("arch='basic'", repr_str)
        self.assertIn('input_dim=32', repr_str)
        self.assertIn('output_dim=16', repr_str)
        self.assertIn('generations=', repr_str)


class TestAILogicGeneratorTraining(unittest.TestCase):
    """Test training-related functionality"""
    
    def setUp(self):
        """Set up training test environment"""
        self.training_generator = AILogicGenerator(
            input_dim=16,
            output_dim=8,
            architecture='basic',
            training_mode=True
        )
    
    def test_training_initialization(self):
        """Test training mode initialization"""
        self.assertTrue(self.training_generator.training_mode)
        self.assertIsNotNone(self.training_generator.X_train)
        self.assertIsNotNone(self.training_generator.y_train)
        self.assertGreater(len(self.training_generator.X_train), 0)
        self.assertEqual(len(self.training_generator.X_train), len(self.training_generator.y_train))
    
    def test_training_data_generation(self):
        """Test training data generation"""
        # Generate training data
        self.training_generator._generate_initial_training_data(num_samples=100)
        
        # Check data properties
        self.assertEqual(len(self.training_generator.X_train), 100)
        self.assertEqual(len(self.training_generator.y_train), 100)
        self.assertEqual(self.training_generator.X_train.shape[1], 16)
        self.assertEqual(self.training_generator.y_train.shape[1], 8)
        
        # Check data ranges
        self.assertTrue(np.all(self.training_generator.X_train >= -1))
        self.assertTrue(np.all(self.training_generator.X_train <= 1))
        self.assertTrue(np.all(self.training_generator.y_train >= -3))
        self.assertTrue(np.all(self.training_generator.y_train <= 3))
    
    def test_model_training(self):
        """Test basic model training"""
        # Reduce training data for faster test
        self.training_generator._generate_initial_training_data(num_samples=50)
        
        # Train for few epochs
        history = self.training_generator.train_model(
            epochs=2, 
            validation_split=0.2, 
            verbose=0
        )
        
        # Check training completed
        self.assertIsInstance(history, tf.keras.callbacks.History)
        self.assertIn('loss', history.history)
        self.assertGreater(len(self.training_generator.training_history), 0)
    
    def test_training_without_mode(self):
        """Test that training fails when training mode is disabled"""
        non_training_gen = AILogicGenerator(training_mode=False)
        
        with self.assertRaises(ValueError):
            non_training_gen.train_model(epochs=1)


class TestAILogicIntegration(unittest.TestCase):
    """Test integration scenarios"""
    
    def setUp(self):
        """Set up integration test environment"""
        self.generator = AILogicGenerator(
            input_dim=64,
            output_dim=64,
            architecture='standard',
            training_mode=False
        )
    
    def test_tensor_integration(self):
        """Test integration with tensor encryption"""
        # Generate logic for tensor use
        logic_vector, metadata = self.generator.generate_session_logic(
            "tensor_session", "tensor_device"
        )
        
        # Reshape for tensor use (8x8)
        logic_tensor = logic_vector.reshape(8, 8)
        
        # Check tensor properties
        self.assertEqual(logic_tensor.shape, (8, 8))
        self.assertEqual(logic_tensor.dtype, np.int8)
        
        # Test basic tensor operations
        test_data = np.random.randint(-128, 127, (8, 8), dtype=np.int8)
        encrypted = np.bitwise_xor(test_data.astype(np.uint8), 
                                  logic_tensor.astype(np.uint8))
        decrypted = np.bitwise_xor(encrypted, logic_tensor.astype(np.uint8))
        
        self.assertTrue(np.array_equal(test_data.astype(np.uint8), decrypted))
    
    def test_multiple_sessions(self):
        """Test handling multiple concurrent sessions"""
        sessions = []
        
        # Generate logic for multiple sessions
        for i in range(10):
            session_id = f"multi_session_{i}"
            device_id = f"device_{i % 3}"  # Some devices used multiple times
            
            logic, metadata = self.generator.generate_session_logic(
                session_id, device_id
            )
            sessions.append((session_id, device_id, logic, metadata))
        
        # Verify all sessions generated successfully
        self.assertEqual(len(sessions), 10)
        
        # Verify sessions with same device but different session ID are different
        device_0_sessions = [(s, l) for s, d, l, m in sessions if d == 'device_0']
        if len(device_0_sessions) > 1:
            for i in range(len(device_0_sessions) - 1):
                self.assertFalse(np.array_equal(
                    device_0_sessions[i][1], 
                    device_0_sessions[i+1][1]
                ))


if __name__ == '__main__':
    # Configure test runner
    unittest.main(verbosity=2, buffer=True)
