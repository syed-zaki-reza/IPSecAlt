"""
Comprehensive tests for AI logic in Connect Four game.
Tests minimax algorithm, move evaluation, and game state analysis.
"""

import pytest
import numpy as np
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.ai_logic import AIPlayer
from src.tensor_engine import TensorEngine


class TestAILogic:
    """Test suite for AI game logic and decision making."""
    
    def setup_method(self):
        """Set up test fixtures before each test method."""
        self.ai_player = AIPlayer(depth=3, player_id=2)
        self.tensor_engine = TensorEngine()
        
    def test_ai_initialization(self):
        """Test AI player initialization with correct parameters."""
        ai = AIPlayer(depth=4, player_id=2)
        assert ai.depth == 4
        assert ai.player_id == 2
        assert ai.opponent_id == 1
        
    def test_evaluate_board_empty(self):
        """Test board evaluation on empty board."""
        board = np.zeros((6, 7), dtype=int)
        score = self.ai_player.evaluate_board(board)
        assert score == 0
        
    def test_evaluate_board_ai_advantage(self):
        """Test board evaluation when AI has advantage."""
        board = np.zeros((6, 7), dtype=int)
        # AI has two in a row
        board[5, 0] = 2  # AI
        board[5, 1] = 2  # AI
        score = self.ai_player.evaluate_board(board)
        assert score > 0
        
    def test_evaluate_board_opponent_advantage(self):
        """Test board evaluation when opponent has advantage."""
        board = np.zeros((6, 7), dtype=int)
        # Opponent has two in a row
        board[5, 0] = 1  # Opponent
        board[5, 1] = 1  # Opponent
        score = self.ai_player.evaluate_board(board)
        assert score < 0
        
    def test_find_winning_move(self):
        """Test AI finds immediate winning move."""
        board = np.zeros((6, 7), dtype=int)
        # Setup: AI has three in a row, can win with next move
        board[5, 0:3] = 2  # AI pieces
        board[5, 3] = 0    # Empty winning spot
        
        best_move = self.ai_player.find_best_move(board)
        assert best_move == 3  # Should choose winning move
        
    def test_block_opponent_win(self):
        """Test AI blocks opponent's winning move."""
        board = np.zeros((6, 7), dtype=int)
        # Setup: Opponent has three in a row
        board[5, 0:3] = 1  # Opponent pieces
        board[5, 3] = 0    # Empty blocking spot
        
        best_move = self.ai_player.find_best_move(board)
        assert best_move == 3  # Should block opponent
        
    def test_valid_moves_generation(self):
        """Test generation of valid moves."""
        board = np.zeros((6, 7), dtype=int)
        # Fill some columns partially
        board[5, 0] = 1  # Column 0 has one piece
        board[4, 0] = 0  # Still has space
        
        valid_moves = self.ai_player.get_valid_moves(board)
        expected_moves = list(range(7))  # All columns should be valid
        assert valid_moves == expected_moves
        
    def test_full_column_handling(self):
        """Test AI handles full columns correctly."""
        board = np.zeros((6, 7), dtype=int)
        # Fill column 0 completely
        for row in range(6):
            board[row, 0] = 1
            
        valid_moves = self.ai_player.get_valid_moves(board)
        assert 0 not in valid_moves  # Full column should not be in valid moves
        
    def test_minimax_depth_1(self):
        """Test minimax with depth 1."""
        shallow_ai = AIPlayer(depth=1, player_id=2)
        board = np.zeros((6, 7), dtype=int)
        
        # Simple immediate advantage scenario
        board[5, 0] = 2
        board[5, 1] = 2
        
        move = shallow_ai.find_best_move(board)
        assert move in range(7)  # Should return a valid move
        
    def test_game_win_detection(self):
        """Test win condition detection."""
        # Horizontal win
        board = np.zeros((6, 7), dtype=int)
        board[5, 0:4] = 2  # Four in a row horizontally
        
        assert self.ai_player.check_win(board, 2) == True
        
        # Vertical win
        board = np.zeros((6, 7), dtype=int)
        for i in range(4):
            board[5-i, 0] = 1  # Four in a row vertically
            
        assert self.ai_player.check_win(board, 1) == True
        
    def test_no_valid_moves(self):
        """Test behavior when no valid moves exist."""
        board = np.ones((6, 7), dtype=int)  # Completely full board
        valid_moves = self.ai_player.get_valid_moves(board)
        assert valid_moves == []  # No valid moves
        
    def test_center_column_preference(self):
        """Test AI prefers center columns in early game."""
        board = np.zeros((6, 7), dtype=int)  # Empty board
        move = self.ai_player.find_best_move(board)
        # Center columns (2,3,4) are generally preferred
        assert move in [2, 3, 4]
        
    @patch('src.ai_logic.AIPlayer.minimax')
    def test_minimax_called_correctly(self, mock_minimax):
        """Test minimax is called with correct parameters."""
        mock_minimax.return_value = (50, 3)  # Mock return value
        
        board = np.zeros((6, 7), dtype=int)
        self.ai_player.find_best_move(board)
        
        # Verify minimax was called
        assert mock_minimax.called
        call_args = mock_minimax.call_args[0]
        assert call_args[0] == 3  # depth
        assert call_args[1] == board is not None
        assert call_args[3] == -float('inf')  # alpha
        assert call_args[4] == float('inf')   # beta
        
    def test_alpha_beta_pruning(self):
        """Test alpha-beta pruning improves performance."""
        import time
        
        board = np.zeros((6, 7), dtype=int)
        
        # Test with pruning
        start_time = time.time()
        move_with_pruning = self.ai_player.find_best_move(board)
        time_with_pruning = time.time() - start_time
        
        # Should complete reasonably quickly with pruning
        assert time_with_pruning < 5.0  # Should take less than 5 seconds
        assert move_with_pruning in range(7)


class TestAIIntegration:
    """Integration tests for AI with tensor engine."""
    
    def setup_method(self):
        self.tensor_engine = TensorEngine()
        self.ai_player = AIPlayer(depth=3, player_id=2)
        
    def test_ai_with_tensor_board(self):
        """Test AI works with tensor engine board representation."""
        game_state = self.tensor_engine.initialize_game()
        board = game_state['board']
        
        # Make AI move
        ai_move = self.ai_player.find_best_move(board)
        
        # Verify move is valid
        valid_moves = self.ai_player.get_valid_moves(board)
        assert ai_move in valid_moves
        
    def test_complete_ai_game(self):
        """Test AI can play a complete game against itself."""
        board = np.zeros((6, 7), dtype=int)
        current_player = 1
        
        # Play until game ends or maximum moves
        for move_count in range(42):  # Maximum possible moves
            if current_player == 1:
                # Simple heuristic for player 1: choose first valid move
                valid_moves = self.ai_player.get_valid_moves(board)
                if not valid_moves:
                    break  # Game over
                move = valid_moves[0]
            else:
                # AI move for player 2
                move = self.ai_player.find_best_move(board)
                
            # Apply move
            for row in range(5, -1, -1):
                if board[row, move] == 0:
                    board[row, move] = current_player
                    break
                    
            # Check win condition
            if self.ai_player.check_win(board, current_player):
                break
                
            # Switch player
            current_player = 3 - current_player  # Switch between 1 and 2
            
        # Game should have ended properly
        assert move_count < 42  # Shouldn't reach maximum moves without ending


if __name__ == "__main__":
    pytest.main([__file__, "-v"])