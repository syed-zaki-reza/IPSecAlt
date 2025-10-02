"""
Tests for tensor engine operations.
Tests matrix operations, game logic, and cryptographic tensor functions.
"""

import pytest
import numpy as np
from unittest.mock import Mock, patch, MagicMock
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.tensor_engine import TensorEngine
from src.ai_logic import AIPlayer


class TestTensorEngine:
    """Test suite for tensor engine core functionality."""
    
    def setup_method(self):
        """Set up test fixtures before each test method."""
        self.engine = TensorEngine()
        
    def test_engine_initialization(self):
        """Test tensor engine initialization."""
        assert self.engine is not None
        assert hasattr(self.engine, 'board_shape')
        assert self.engine.board_shape == (6, 7)
        
    def test_game_initialization(self):
        """Test game state initialization."""
        game_state = self.engine.initialize_game()
        
        assert 'board' in game_state
        assert 'current_player' in game_state
        assert 'game_over' in game_state
        assert 'winner' in game_state
        
        board = game_state['board']
        assert board.shape == (6, 7)
        assert np.all(board == 0)  # Board should be empty
        
    def test_valid_move_detection(self):
        """Test detection of valid moves."""
        board = np.zeros((6, 7), dtype=int)
        
        # All columns should be valid in empty board
        valid_moves = self.engine.get_valid_moves(board)
        assert valid_moves == list(range(7))
        
    def test_full_column_handling(self):
        """Test handling of full columns."""
        board = np.zeros((6, 7), dtype=int)
        # Fill column 0
        for row in range(6):
            board[row, 0] = 1
            
        valid_moves = self.engine.get_valid_moves(board)
        assert 0 not in valid_moves  # Full column should not be valid
        
    def test_move_application(self):
        """Test applying moves to the board."""
        board = np.zeros((6, 7), dtype=int)
        
        # Apply move to column 3
        new_board, row_played = self.engine.apply_move(board, 3, 1)
        
        assert row_played == 5  # Should be bottom row
        assert new_board[5, 3] == 1
        assert np.sum(new_board) == 1  # Only one piece placed
        
    def test_stack_moves(self):
        """Test stacking moves in the same column."""
        board = np.zeros((6, 7), dtype=int)
        
        # Make two moves in column 2
        board, row1 = self.engine.apply_move(board, 2, 1)
        board, row2 = self.engine.apply_move(board, 2, 2)
        
        assert row1 == 5  # First move at bottom
        assert row2 == 4  # Second move above first
        assert board[5, 2] == 1
        assert board[4, 2] == 2
        
    def test_win_detection_horizontal(self):
        """Test horizontal win detection."""
        board = np.zeros((6, 7), dtype=int)
        # Create horizontal win for player 1
        board[5, 0:4] = 1
        
        assert self.engine.check_win(board, 1) == True
        assert self.engine.check_win(board, 2) == False
        
    def test_win_detection_vertical(self):
        """Test vertical win detection."""
        board = np.zeros((6, 7), dtype=int)
        # Create vertical win for player 2
        for i in range(4):
            board[5-i, 3] = 2
            
        assert self.engine.check_win(board, 2) == True
        assert self.engine.check_win(board, 1) == False
        
    def test_win_detection_diagonal(self):
        """Test diagonal win detection."""
        board = np.zeros((6, 7), dtype=int)
        # Create diagonal win (bottom-left to top-right)
        for i in range(4):
            board[5-i, i] = 1
            
        assert self.engine.check_win(board, 1) == True
        
    def test_win_detection_anti_diagonal(self):
        """Test anti-diagonal win detection."""
        board = np.zeros((6, 7), dtype=int)
        # Create anti-diagonal win (bottom-right to top-left)
        for i in range(4):
            board[5-i, 6-i] = 2
            
        assert self.engine.check_win(board, 2) == True
        
    def test_no_win_empty_board(self):
        """Test win detection on empty board."""
        board = np.zeros((6, 7), dtype=int)
        assert self.engine.check_win(board, 1) == False
        assert self.engine.check_win(board, 2) == False
        
    def test_draw_detection(self):
        """Test draw condition detection."""
        # Create a full board with no wins (alternating players)
        board = np.zeros((6, 7), dtype=int)
        for row in range(6):
            for col in range(7):
                # Alternate between players
                board[row, col] = (row + col) % 2 + 1
                
        assert self.engine.check_draw(board) == True
        
    def test_not_draw_with_empty_spaces(self):
        """Test draw detection with empty spaces."""
        board = np.zeros((6, 7), dtype=int)
        board[5, 0] = 1  # One piece, rest empty
        assert self.engine.check_draw(board) == False
        
    def test_not_draw_with_win(self):
        """Test draw detection when there's a win."""
        board = np.zeros((6, 7), dtype=int)
        board[5, 0:4] = 1  # Winning line
        assert self.engine.check_draw(board) == False
        
    def test_game_state_update(self):
        """Test complete game state update after move."""
        game_state = self.engine.initialize_game()
        
        updated_state = self.engine.make_move(game_state, 3)
        
        assert updated_state['board'][5, 3] == 1  # Player 1's move
        assert updated_state['current_player'] == 2  # Switch to player 2
        assert updated_state['moves'] == [3]  # Recorded move
        
    def test_winning_move_detection(self):
        """Test detection of winning moves."""
        board = np.zeros((6, 7), dtype=int)
        # Setup: player 1 has three in a row
        board[5, 0:3] = 1
        
        # Column 3 should be winning move
        is_winning = self.engine.is_winning_move(board, 3, 1)
        assert is_winning == True
        
    def test_non_winning_move(self):
        """Test detection of non-winning moves."""
        board = np.zeros((6, 7), dtype=int)
        board[5, 0] = 1  # Single piece
        
        # No move should be winning from this position
        for col in range(7):
            is_winning = self.engine.is_winning_move(board, col, 1)
            assert is_winning == False


class TestTensorOperations:
    """Test suite for mathematical tensor operations."""
    
    def setup_method(self):
        self.engine = TensorEngine()
        
    def test_tensor_creation(self):
        """Test creation of game state tensors."""
        board = np.zeros((6, 7), dtype=int)
        board[5, 0] = 1
        board[5, 1] = 2
        
        tensor = self.engine.board_to_tensor(board)
        
        # Tensor should have appropriate shape and values
        assert len(tensor.shape) == 3  # Channel last format
        assert tensor.shape[2] == 3    # 3 channels: player1, player2, empty
        
    def test_tensor_normalization(self):
        """Test tensor value normalization."""
        test_tensor = np.random.rand(6, 7, 3) * 100  # Large values
        
        normalized = self.engine.normalize_tensor(test_tensor)
        
        # Values should be normalized (typically between 0-1 or -1-1)
        assert np.max(np.abs(normalized)) <= 1.0
        
    def test_matrix_multiplication(self):
        """Test tensor matrix multiplication."""
        A = np.random.rand(6, 7)
        B = np.random.rand(7, 6)
        
        result = self.engine.matrix_multiply(A, B)
        
        assert result.shape == (6, 6)
        # Verify multiplication is correct
        expected = np.dot(A, B)
        np.testing.assert_array_almost_equal(result, expected)
        
    def test_tensor_contraction(self):
        """Test tensor contraction operations."""
        tensor = np.random.rand(6, 7, 3)
        
        contracted = self.engine.tensor_contraction(tensor, (0, 1))
        
        # Should contract first two dimensions
        assert contracted.shape == (3,)
        
    def test_eigenvalue_calculation(self):
        """Test eigenvalue computation for square matrices."""
        # Create symmetric matrix for real eigenvalues
        matrix = np.random.rand(5, 5)
        symmetric_matrix = (matrix + matrix.T) / 2
        
        eigenvalues = self.engine.compute_eigenvalues(symmetric_matrix)
        
        assert len(eigenvalues) == 5
        # Eigenvalues of real symmetric matrix should be real
        assert np.all(np.isreal(eigenvalues))
        

class TestCryptographicTensorOperations:
    """Test suite for cryptographic tensor operations."""
    
    def setup_method(self):
        self.engine = TensorEngine()
        
    def test_tensor_encryption(self):
        """Test encryption of tensor data."""
        original_tensor = np.random.rand(6, 7, 3)
        key = b'test_key_16_bytes!!'
        
        encrypted = self.engine.encrypt_tensor(original_tensor, key)
        
        # Encrypted tensor should be different
        assert not np.array_equal(encrypted, original_tensor)
        assert encrypted.shape == original_tensor.shape
        
    def test_tensor_decryption(self):
        """Test decryption of tensor data."""
        original_tensor = np.random.rand(4, 4, 2)
        key = b'decryption_test_key'
        
        encrypted = self.engine.encrypt_tensor(original_tensor, key)
        decrypted = self.engine.decrypt_tensor(encrypted, key)
        
        # Should recover original data
        np.testing.assert_array_almost_equal(decrypted, original_tensor)
        
    def test_tensor_hash(self):
        """Test tensor hashing for integrity verification."""
        tensor = np.random.rand(6, 7, 3)
        
        hash_value = self.engine.tensor_hash(tensor)
        
        assert isinstance(hash_value, bytes)
        assert len(hash_value) == 32  # SHA-256 hash length
        
    def test_hash_consistency(self):
        """Test hash consistency for same tensors."""
        tensor = np.random.rand(5, 5, 2)
        
        hash1 = self.engine.tensor_hash(tensor)
        hash2 = self.engine.tensor_hash(tensor)
        
        assert hash1 == hash2  # Same tensor should produce same hash
        
    def test_hash_sensitivity(self):
        """Test hash sensitivity to small changes."""
        tensor1 = np.random.rand(4, 4, 3)
        tensor2 = tensor1.copy()
        tensor2[0, 0, 0] += 0.0001  # Tiny change
        
        hash1 = self.engine.tensor_hash(tensor1)
        hash2 = self.engine.tensor_hash(tensor2)
        
        assert hash1 != hash2  # Hashes should be different
        
    def test_secure_random_tensor(self):
        """Test generation of cryptographically secure random tensors."""
        shape = (3, 3, 2)
        random_tensor = self.engine.secure_random_tensor(shape)
        
        assert random_tensor.shape == shape
        # Values should be properly distributed
        assert np.min(random_tensor) >= 0
        assert np.max(random_tensor) <= 1


class TestTensorEngineIntegration:
    """Integration tests for tensor engine with other components."""
    
    def setup_method(self):
        self.engine = TensorEngine()
        self.ai_player = AIPlayer(depth=2, player_id=2)
        
    def test_ai_with_tensor_engine(self):
        """Test AI integration with tensor engine."""
        game_state = self.engine.initialize_game()
        
        # AI makes a move using tensor engine's board
        ai_move = self.ai_player.find_best_move(game_state['board'])
        
        # Apply move through tensor engine
        updated_state = self.engine.make_move(game_state, ai_move)
        
        # Verify move was applied correctly
        assert updated_state['board'][5, ai_move] == 1
        assert updated_state['current_player'] == 2
        
    def test_complete_game_flow(self):
        """Test complete game flow with tensor engine."""
        game_state = self.engine.initialize_game()
        
        # Play several moves
        for move_num in range(10):
            current_player = game_state['current_player']
            
            if current_player == 2:  # AI's turn
                move = self.ai_player.find_best_move(game_state['board'])
            else:  # Simple heuristic for player 1
                valid_moves = self.engine.get_valid_moves(game_state['board'])
                move = valid_moves[0] if valid_moves else None
                
            if move is None:
                break  # No valid moves
                
            game_state = self.engine.make_move(game_state, move)
            
            # Check game end conditions
            if game_state['game_over']:
                break
                
        # Game should have proper end state
        assert 'game_over' in game_state
        assert 'winner' in game_state
        
    def test_game_state_serialization(self):
        """Test game state serialization and deserialization."""
        original_state = self.engine.initialize_game()
        original_state = self.engine.make_move(original_state, 3)
        original_state = self.engine.make_move(original_state, 2)
        
        # Serialize
        serialized = self.engine.serialize_game_state(original_state)
        
        # Should be JSON serializable
        import json
        json_str = json.dumps(serialized)
        
        # Deserialize
        deserialized_state = self.engine.deserialize_game_state(serialized)
        
        # Should recover original state
        assert deserialized_state['current_player'] == original_state['current_player']
        np.testing.assert_array_equal(
            deserialized_state['board'], 
            original_state['board']
        )
        
    def test_performance_large_tensors(self):
        """Test performance with larger tensors."""
        import time
        
        large_tensor = np.random.rand(100, 100, 10)
        
        start_time = time.time()
        result = self.engine.normalize_tensor(large_tensor)
        end_time = time.time()
        
        # Should complete within reasonable time
        assert end_time - start_time < 5.0  # Less than 5 seconds
        assert result.shape == large_tensor.shape


if __name__ == "__main__":
    pytest.main([__file__, "-v"])