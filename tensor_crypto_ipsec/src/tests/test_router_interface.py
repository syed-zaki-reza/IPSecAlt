# [file name]: src/tests/test_router_interface.py
"""
Comprehensive tests for Router Interface
"""

import pytest
import tempfile
import numpy as np
from unittest.mock import Mock, patch
import socket

from src import RouterInterface, RouterConfig, ProtocolType, SessionState
from .conftest import key_manager, dictionary_manager, tensor_engine, ai_logic_generator


class TestRouterInterface:
    """Test cases for RouterInterface class"""
    
    def test_initialization(self, key_manager, dictionary_manager, tensor_engine, ai_logic_generator):
        """Test router interface initialization"""
        config = RouterConfig(
            interface_name='test_interface',
            listen_ip='127.0.0.1',
            listen_port=0,  # Use ephemeral port
            max_connections=100,
            buffer_size=8192,
            timeout_seconds=30.0,
            enable_encryption=True,
            enable_compression=True,
            security_level='high',
            traffic_shaping=True,
            quality_of_service=True,
            hardware_acceleration=False
        )
        
        router = RouterInterface(
            config=config,
            key_manager=key_manager,
            dictionary_manager=dictionary_manager,
            tensor_engine=tensor_engine,
            ai_logic_generator=ai_logic_generator
        )
        
        assert router.config.interface_name == 'test_interface'
        assert router.config.security_level == 'high'
        assert router.config.enable_encryption == True
        
    @patch('socket.socket')
    def test_packet_processing(self, mock_socket, key_manager, dictionary_manager, tensor_engine, ai_logic_generator):
        """Test packet processing functionality"""
        # Create router with mock socket
        config = RouterConfig(
            interface_name='test_interface',
            listen_ip='127.0.0.1',
            listen_port=0,
            max_connections=10,
            buffer_size=1024,
            timeout_seconds=5.0,
            enable_encryption=True,
            enable_compression=False,  # Disable compression for simpler testing
            security_level='basic',
            traffic_shaping=False,
            quality_of_service=False,
            hardware_acceleration=False
        )
        
        router = RouterInterface(
            config=config,
            key_manager=key_manager,
            dictionary_manager=dictionary_manager,
            tensor_engine=tensor_engine,
            ai_logic_generator=ai_logic_generator
        )
        
        # Create mock session
        session_id = 'test_session_123'
        source_ip = '192.168.1.100'
        source_port = 54321
        
        # Test session creation
        session = router._get_or_create_session(12345, source_ip, source_port)
        assert session is not None
        assert session.session_id == f"{source_ip}:{source_port}:12345"
        assert session.state == SessionState.HANDSHAKE
        
    def test_session_management(self, key_manager, dictionary_manager, tensor_engine, ai_logic_generator):
        """Test session management functionality"""
        config = RouterConfig(
            interface_name='test_interface',
            listen_ip='127.0.0.1',
            listen_port=0,
            max_connections=50,
            buffer_size=2048,
            timeout_seconds=10.0,
            enable_encryption=False,  # Disable encryption for simpler testing
            enable_compression=False,
            security_level='basic',
            traffic_shaping=False,
            quality_of_service=False,
            hardware_acceleration=False
        )
        
        router = RouterInterface(
            config=config,
            key_manager=key_manager,
            dictionary_manager=dictionary_manager,
            tensor_engine=tensor_engine,
            ai_logic_generator=ai_logic_generator
        )
        
        # Create multiple sessions
        sessions = []
        for i in range(5):
            session = router._get_or_create_session(1000 + i, f'192.168.1.{i+1}', 50000 + i)
            assert session is not None
            sessions.append(session)
        
        # Verify sessions are tracked
        assert len(router.sessions) == 5
        
        # Test session listing
        active_sessions = router.list_sessions(SessionState.HANDSHAKE)
        assert len(active_sessions) == 5
        
        # Test session info retrieval
        session_info = router.get_session_info(sessions[0].session_id)
        assert session_info is not None
        assert session_info.session_id == sessions[0].session_id
        
    def test_performance_metrics(self, key_manager, dictionary_manager, tensor_engine, ai_logic_generator):
        """Test performance metrics collection"""
        config = RouterConfig(
            interface_name='test_interface',
            listen_ip='127.0.0.1',
            listen_port=0,
            max_connections=10,
            buffer_size=1024,
            timeout_seconds=5.0,
            enable_encryption=False,
            enable_compression=False,
            security_level='basic',
            traffic_shaping=False,
            quality_of_service=False,
            hardware_acceleration=False
        )
        
        router = RouterInterface(
            config=config,
            key_manager=key_manager,
            dictionary_manager=dictionary_manager,
            tensor_engine=tensor_engine,
            ai_logic_generator=ai_logic_generator
        )
        
        # Create some session activity
        for i in range(3):
            router._get_or_create_session(2000 + i, f'10.0.0.{i+1}', 60000 + i)
        
        # Check performance metrics
        metrics = router.get_performance_metrics()
        
        assert metrics['total_sessions'] >= 3
        assert metrics['active_sessions'] >= 3
        assert metrics['packets_processed'] >= 0
        assert 'uptime_seconds' in metrics
        assert 'memory_usage_mb' in metrics


class TestRouterIntegration:
    """Integration tests for RouterInterface"""
    
    def test_integration_with_crypto_components(self, key_manager, dictionary_manager, tensor_engine, ai_logic_generator):
        """Test integration with cryptographic components"""
        config = RouterConfig(
            interface_name='crypto_integration_test',
            listen_ip='127.0.0.1',
            listen_port=0,
            max_connections=20,
            buffer_size=4096,
            timeout_seconds=15.0,
            enable_encryption=True,  # Enable encryption for integration test
            enable_compression=True,
            security_level='standard',
            traffic_shaping=True,
            quality_of_service=True,
            hardware_acceleration=False
        )
        
        router = RouterInterface(
            config=config,
            key_manager=key_manager,
            dictionary_manager=dictionary_manager,
            tensor_engine=tensor_engine,
            ai_logic_generator=ai_logic_generator
        )
        
        # Create session with encryption
        session = router._get_or_create_session(3000, '172.16.1.100', 40000)
        
        # Verify cryptographic resources were created
        assert session.session_key_id is not None
        assert session.dictionary_id is not None
        assert session.encryption_level == 'standard'
        
        # Test packet encryption and decryption
        test_payload = b'This is a test payload for encryption'
        
        # Mock the tensor engine encryption
        with patch.object(tensor_engine, 'encrypt_data') as mock_encrypt:
            mock_encrypt.return_value = (b'encrypted_data', {'tensor_hash': 'test_hash'})
            
            # This would normally be called by send_packet
            encrypted_payload = router._encrypt_packet(test_payload, session)
            
            mock_encrypt.assert_called_once()
        
        # Mock the tensor engine decryption  
        with patch.object(tensor_engine, 'decrypt_data') as mock_decrypt:
            mock_decrypt.return_value = test_payload
            
            decrypted_payload = router._decrypt_packet(b'encrypted_data', session)
            
            mock_decrypt.assert_called_once()
            assert decrypted_payload == test_payload
    
    def test_traffic_priority_queues(self, key_manager, dictionary_manager, tensor_engine, ai_logic_generator):
        """Test traffic priority queue functionality"""
        config = RouterConfig(
            interface_name='priority_test',
            listen_ip='127.0.0.1',
            listen_port=0,
            max_connections=15,
            buffer_size=2048,
            timeout_seconds=10.0,
            enable_encryption=False,
            enable_compression=False,
            security_level='basic',
            traffic_shaping=True,  # Enable traffic shaping
            quality_of_service=True,
            hardware_acceleration=False
        )
        
        router = RouterInterface(
            config=config,
            key_manager=key_manager,
            dictionary_manager=dictionary_manager,
            tensor_engine=tensor_engine,
            ai_logic_generator=ai_logic_generator
        )
        
        # Test priority determination
        test_packet = b'\x00' * 50  # Small control-like packet
        test_address = ('192.168.1.50', 12345)
        
        priority = router._determine_packet_priority(test_packet, test_address)
        
        # Small packets should get high priority
        assert priority.value in ['real_time', 'high', 'medium']
        
        # Test queueing mechanism
        router._queue_packet(test_packet, test_address)
        
        # Verify packet was queued in appropriate priority queue
        assert router.traffic_queues[priority].qsize() > 0
    
    @pytest.mark.slow
    def test_session_cleanup(self, key_manager, dictionary_manager, tensor_engine, ai_logic_generator):
        """Test automatic session cleanup"""
        import time
        
        config = RouterConfig(
            interface_name='cleanup_test',
            listen_ip='127.0.0.1',
            listen_port=0,
            max_connections=10,
            buffer_size=1024,
            timeout_seconds=2.0,  # Short timeout for testing
            enable_encryption=False,
            enable_compression=False,
            security_level='basic',
            traffic_shaping=False,
            quality_of_service=False,
            hardware_acceleration=False
        )
        
        router = RouterInterface(
            config=config,
            key_manager=key_manager,
            dictionary_manager=dictionary_manager,
            tensor_engine=tensor_engine,
            ai_logic_generator=ai_logic_generator
        )
        
        # Create sessions
        for i in range(3):
            router._get_or_create_session(4000 + i, f'10.1.1.{i+1}', 70000 + i)
        
        initial_count = len(router.sessions)
        assert initial_count == 3
        
        # Wait for cleanup to run (cleanup runs every 30 seconds in background)
        time.sleep(35)
        
        # Force cleanup check
        router._cleanup_expired_sessions()
        
        # All sessions should be cleaned up due to inactivity
        final_count = len(router.sessions)
        assert final_count == 0
        
    def test_error_handling(self, key_manager, dictionary_manager, tensor_engine, ai_logic_generator):
        """Test error handling in router operations"""
        config = RouterConfig(
            interface_name='error_test',
            listen_ip='127.0.0.1',
            listen_port=0,
            max_connections=5,
            buffer_size=512,
            timeout_seconds=5.0,
            enable_encryption=True,
            enable_compression=False,
            security_level='basic',
            traffic_shaping=False,
            quality_of_service=False,
            hardware_acceleration=False
        )
        
        router = RouterInterface(
            config=config,
            key_manager=key_manager,
            dictionary_manager=dictionary_manager,
            tensor_engine=tensor_engine,
            ai_logic_generator=ai_logic_generator
        )
        
        # Test with invalid session
        invalid_session_id = 'non_existent_session'
        session_info = router.get_session_info(invalid_session_id)
        assert session_info is None
        
        # Test error metrics
        initial_errors = router.performance_metrics.error_count
        
        # Simulate an error (e.g., trying to process malformed packet)
        try:
            router._process_packet((b'invalid_packet_data', ('1.2.3.4', 12345)), 'medium')
        except Exception:
            pass  # Expected to fail
        
        # Error count should be incremented
        assert router.performance_metrics.error_count > initial_errors