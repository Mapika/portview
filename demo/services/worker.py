#!/usr/bin/env python3
"""Demo service: a background worker serving on :5000."""
import http.server
import socketserver

with socketserver.TCPServer(("127.0.0.1", 5000), http.server.SimpleHTTPRequestHandler) as httpd:
    httpd.serve_forever()
