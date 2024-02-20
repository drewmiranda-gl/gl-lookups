from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import threading
import time

class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        time.sleep(5)
        self.send_response(200)
        self.end_headers()
        message =  threading.current_thread().getName()
        self.wfile.write(bytes(message, "utf-8"))
        self.wfile.write(bytes("\n", "utf-8"))
        return

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

if __name__ == '__main__':
    server = ThreadedHTTPServer(('localhost', 8080), Handler)
    print('Starting server, use <Ctrl-C> to stop')
    server.serve_forever()
