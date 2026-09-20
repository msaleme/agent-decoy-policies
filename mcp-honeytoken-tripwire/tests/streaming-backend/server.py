# Copyright (c) 2026 msaleme. Licensed under the MIT License.
"""Isolated test fixture. Contains only a synthetic decoy, never registration data."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys
import time

DECOY = b"acct_DECOY_9x1f-do-not-use"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def do_POST(self):
        command = self.rfile.read(int(self.headers.get("content-length", "0")))
        if command == b"clean":
            self.send_response(200)
            self.send_header("content-type", "text/plain")
            self.send_header("content-length", "5")
            self.end_headers()
            self.wfile.write(b"clean")
            return
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("transfer-encoding", "chunked")
        self.end_headers()
        try:
            payload = b"data: " + DECOY + b"\n\n"
            if command == b"oversized":
                payload += b"x" * 8192
            self.wfile.write(f"{len(payload):x}\r\n".encode() + payload + b"\r\n")
            self.wfile.flush()
            if command == b"active":
                # Ten-second safety bound; chunks every 100 ms prevent idle expiry.
                # Total bytes remain below 4096, isolating the response deadline.
                for _ in range(100):
                    time.sleep(0.1)
                    self.wfile.write(b"3\r\n:\n\n\r\n")
                    self.wfile.flush()
            if command == b"malformed":
                self.wfile.write(b"NOT-HEX\r\n")
                self.close_connection = True
            else:
                self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True


server = ThreadingHTTPServer(("0.0.0.0", 80), Handler)
print("Listening on streaming fixture", file=sys.stderr, flush=True)
server.serve_forever()
