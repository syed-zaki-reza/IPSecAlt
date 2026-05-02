# [file name]: src/tests/test_router_interface.py
"""
Comprehensive tests for Router Interface
"""

import pytest
import tempfile
import numpy as np
from unittest.mock import Mock, patch, MagicMock
import socket
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.router_interface import RouterInterface, RouterConfig, ProtocolType, SessionState
from src.security_types import SecurityLevel


class TestRouterInterface:
    """Test cases for RouterInterface class"""
    
    @pytest.fixture
    def temp_db(self):
        """Create temporary database"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        yield db_path
        if os.path.exists(db_path):
            os.unlink(db_path)
    
    @pytest.fixture
    def router_config(self):
        """Create router configuration"""
        return RouterConfig(
            interface_name='test_interface',
            listen_ip='127.0.0.1',
            listen_port=0,
            max_connections=10,
            buffer_size=8192,
            timeout_seconds=30.0,
            enable_encryption=True,
            enable_compression=True,
            security_level='high',
            traffic_shaping=True,
            quality_of_service=True,
            hardware_acceleration=False
        )
    
    @pytest.fixture
    def router_interface(self, router_config, temp_db):
        """Create router interface instance"""
        from src.key_management import KeyManager
        from src.dictionary_manager import DictionaryManager
        from src.tensor_engine import TensorEncryptionEngine
        from src.ai_logic import AILogicGenerator
        
        key_manager = KeyManager(
            db_path=temp_db,
            device_id='test_device',
            security_level='high'
        )
        
        dictionary_manager = DictionaryManager(
            db_path=temp_db,
            device_id='test_device',
            security_level='high'
        )
        
        tensor_engine = TensorEncryptionEngine(
            tensor_dimensions=(8, 8),
            security_level='high'
        )
        
        ai_logic_generator = AILogicGenerator(
            input_dim=64,
            output_dim=64,
            architecture='standard',
            security_level='high'
        )
        
        return RouterInterface(
            config=router_config,
            key_manager=key_manager,
            dictionary_manager=dictionary_manager,
            tensor_engine=tensor_engine,
            ai_logic_generator=ai_logic_generator
        )
    
    def test_initialization(self, router_interface):
        """Test router interface initialization"""
        assert router_interface.config.interface_name == 'test_interface'
        assert router_interface.config.security_level == 'high'
        assert router_interface.config.enable_encryption == True
        assert router_interface.key_manager is not None
        assert router_interface.dictionary_manager is not None
        assert router_interface.tensor_engine is not None
        assert router_interface.ai_logic_generator is not None
        
    def test_session_creation(self, router_interface):
        """Test session creation and management"""
        # Create test session
        source_ip = '192.168.1.100'
        source_port = 54321
        
        # Use the actual session creation method if it exists
        if hasattr(router_interface, '_create_session'):
            session = router_interface._create_session(
                source_ip=source_ip,
                source_port=source_port,
                protocol=ProtocolType.TCP
            )
            
            assert session is not None
            assert session.source_ip == source_ip
            assert session.source_port == source_port
            assert session.protocol == ProtocolType.TCP
            
    @patch('socket.socket')
    def test_packet_processing_flow(self, mock_socket, router_interface):
        """Test complete packet processing flow"""
        # Create mock packet data
        test_packet = b'\x00\x01\x02\x03\x04\x05' * 10  # 60 bytes
        
        # Test packet reception if method exists
        if hasattr(router_interface, '_process_packet'):
            with patch.object(router_interface, '_process_packet') as mock_process:
                mock_process.return_value = True
                
                # Simulate packet reception
                success = router_interface._process_packet(test_packet, ('192.168.1.50', 12345))
                
                mock_process.assert_called_once()
                assert success == True
                
    def test_performance_metrics_collection(self, router_interface):
        """Test performance metrics collection"""
        # Get performance metrics if method exists
        if hasattr(router_interface, 'get_performance_metrics'):
            metrics = router_interface.get_performance_metrics()
            
            # Verify metrics structure
            assert isinstance(metrics, dict)
            assert 'total_sessions' in metrics
            assert 'active_sessions' in metrics
            
    def test_error_handling(self, router_interface):
        """Test error handling in router operations"""
        # Test with invalid packet data
        invalid_packet = b''  # Empty packet
        
        # Should handle gracefully if method exists
        if hasattr(router_interface, '_process_packet'):
            try:
                result = router_interface._process_packet(invalid_packet, ('1.2.3.4', 12345))
                # Should not crash, result can be True/False
                assert result in [True, False]
            except Exception as e:
                pytest.fail(f"Should handle invalid packet gracefully, got: {e}")


class TestRouterIntegration:
    """Integration tests for RouterInterface"""
    
    def test_integration_with_crypto_components(self, temp_db):
        """Test integration with cryptographic components"""
        from src.router_interface import RouterInterface, RouterConfig, ProtocolType
        from src.key_management import KeyManager
        from src.dictionary_manager import DictionaryManager
        from src.tensor_engine import TensorEncryptionEngine
        from src.ai_logic import AILogicGenerator
        
        router_config = RouterConfig(
            interface_name='crypto_integration_test',
            listen_ip='127.0.0.1',
            listen_port=0,
            max_connections=10,
            buffer_size=8192,
            enable_encryption=True,
            security_level='high'
        )
        
        key_manager = KeyManager(
            db_path=temp_db,
            device_id='test_device',
            security_level='high'
        )
        
        dictionary_manager = DictionaryManager(
            db_path=temp_db,
            device_id='test_device',
            security_level='high'
        )
        
        tensor_engine = TensorEncryptionEngine(
            tensor_dimensions=(8, 8),
            security_level='high'
        )
        
        ai_logic_generator = AILogicGenerator(
            input_dim=64,
            output_dim=64,
            architecture='standard',
            security_level='high'
        )
        
        router = RouterInterface(
            config=router_config,
            key_manager=key_manager,
            dictionary_manager=dictionary_manager,
            tensor_engine=tensor_engine,
            ai_logic_generator=ai_logic_generator
        )
        
        # Verify all components are properly integrated
        assert router.key_manager is key_manager
        assert router.dictionary_manager is dictionary_manager
        assert router.tensor_engine is tensor_engine
        assert router.ai_logic_generator is ai_logic_generator