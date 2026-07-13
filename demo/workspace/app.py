import http.server
from http.server import SimpleHTTPRequestHandler
import random

class SudokuHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/sudoku':
            board = self.generate_sudoku()
            response = self.create_response(board)
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(response.encode())
        else:
            super().do_GET()

    def generate_sudoku(self):
        # Generate a valid Sudoku board
        board = [[0]*9 for _ in range(9)]
        self.fill_board(board)
        return board

    def fill_board(self, board):
        # Fill the board with numbers 1-9
        for i in range(9):
            for j in range(9):
                if board[i][j] == 0:
                    numbers = list(range(1, 10))
                    random.shuffle(numbers)
                    for num in numbers:
                        if self.is_valid(board, i, j, num):
                            board[i][j] = num
                            break

    def is_valid(self, board, row, col, num):
        # Check if a number can be placed in a cell
        for i in range(9):
            if board[row][i] == num or board[i][col] == num:
                return False
        start_row, start_col = 3 * (row // 3), 3 * (col // 3)
        for i in range(3):
            for j in range(3):
                if board[start_row + i][start_col + j] == num:
                    return False
        return True

    def create_response(self, board):
        # Create an HTML response with the Sudoku board
        response = '<!DOCTYPE html><html><head><title>Sudoku</title></head><body>'
        response += '<h1>Sudoku</h1>'
        response += '<table>
'
        for i in range(9):
            response += '<tr>'
            for j in range(9):
                if board[i][j] == 0:
                    response += '<td><input type=