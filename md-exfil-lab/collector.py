#!/usr/bin/env python3
"""
Attacker-controlled collector for the markdown-image exfiltration lab.

Serves a 1x1 pixel and LOGS every request line (including the query string) to
exfil.log. In the real attacks (CamoLeak / EchoLeak) this is just the attacker's
web-server access log — the secret arrives in the URL when the victim's chat
client auto-fetches the image the model was tricked into emitting.

Run:  python collector.py    (listens on http://127.0.0.1:9009)
"""
import os
import datetime
import http.server
import socketserver

HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(HERE, "exfil.log")
# a minimal 1x1 transparent GIF
PIXEL = bytes.fromhex(
    "47494638396101000100800000000000ffffff21f9040100000000"
    "2c00000000010001000002024401003b")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        ts = datetime.datetime.now().isoformat(timespec="seconds")
        line = f"{ts}  GET {self.path}  (from {self.client_address[0]})"
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        print("[collector] " + line, flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Content-Length", str(len(PIXEL)))
        self.end_headers()
        self.wfile.write(PIXEL)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    open(LOG, "w", encoding="utf-8").close()   # fresh log each run
    with socketserver.TCPServer(("127.0.0.1", 9009), Handler) as httpd:
        print(f"collector listening on http://127.0.0.1:9009  (log: {LOG})",
              flush=True)
        httpd.serve_forever()
