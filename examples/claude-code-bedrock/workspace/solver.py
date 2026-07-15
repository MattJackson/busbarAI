# solver.py
def is_valid(board, row, col, num):
    for i in range(9):
        if board[row][i] == num or board[i][col] == num:
            return False
    start_row, start_col = 3 * (row // 3), 3 * (col // 3)
    for i in range(3):
        for j in range(3):
            if board[start_row + i][start_col + j] == num:
                return False
    return True

def solve_sudoku(board):
    for i in range(9):
        for j in range(9):
            if board[i][j] == 0:
                for num in range(1, 10):
                    if is_valid(board, i, j, num):
                        board[i][j] = num
                        if solve_sudoku(board):
                            return True
                        board[i][j] = 0
                return False
    return True

def print_board(board):
    for i in range(9):
        for j in range(9):
            print(board[i][j], end=' ')
        print()

if __name__ == '__main__':
    board = [[0 for _ in range(9)] for _ in range(9)]
    if solve_sudoku(board):
        print_board(board)
    else:
        print('No solution exists')