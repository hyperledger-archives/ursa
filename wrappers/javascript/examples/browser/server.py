#!/usr/bin/env python3
import http.server
import socketserver

PORT = 8000

handler = http.server.SimpleHTTPRequestHandler
handler.extensions_map['.wasm'] = 'application/wasm'

print('Server accepting requests on port {}'.format(PORT))

with socketserver.TCPServer(('', PORT), handler) as httpd:
    httpd.serve_forever()
