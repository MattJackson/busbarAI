# app.py
from http.server import SimpleHTTPRequestHandler, HTTPServer
import threading

class SudokuHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/sudoku':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = """
            <html>
            <head><title>Sudoku</title></head>
            <body>
            <h1>Sudoku</h1>
            <table border='1'>
            """ + ''.join(f'<tr>{''.join(f"<td><input type=\"text\" size=\"1\" maxlength=\"1\"></td>" for _ in range(9))}</tr>' for _ in range(9)) + """
            </table>
            </body>
            </html>
            """ 
            self.wfile.write(html.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

def run(server_class=HTTPServer, handler_class=SudokuHandler):
    server_address = ('', 8000)
    httpd = server_class(server_address, handler_class)
    print('Server running at http://localhost:8000/sudoku...')
    httpd.serve_forever()

if __name__ == '__main__':
    run()