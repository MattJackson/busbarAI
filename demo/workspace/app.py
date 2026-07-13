from http.server import SimpleHTTPRequestHandler, HTTPServer
import threading

# Sudoku game HTML content
SUDOKU_HTML = '''<!DOCTYPE html>
<html>
<head>
    <title>Sudoku Game</title>
    <style>
        table { border-collapse: collapse; }
        td { width: 30px; height: 30px; text-align: center; border: 1px solid black; }
    </style>
</head>
<body>
    <table>
        <tr><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>
        <tr><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>
        <tr><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>
        <tr><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>
        <tr><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>
        <tr><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>
        <tr><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>
        <tr><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>
        <tr><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>
    </table>
</body>
</html>'''

class SudokuHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/sudoku':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(SUDOKU_HTML.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

def run(server_class=HTTPServer, handler_class=SudokuHandler):
    server_address = ('', 8000)
    httpd = server_class(server_address, handler_class)
    print('Starting sudoku server...')
    httpd.serve_forever()

# Run the server in a separate thread
thread = threading.Thread(target=run)
thread.start()