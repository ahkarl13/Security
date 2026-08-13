#!/usr/bin/env python3
"""Exfil-capture collector for the Agentic-MCP PoC.

Logs the full inbound request — method, path+query, Host/User-Agent, and body — so ANY
exfil channel the agent uses (image URL, fetch, tool arg echoed to a URL) is captured with
the planted canary. Benign: it only records; it never returns anything sensitive.

Local test:  python collector.py                 (binds 0.0.0.0:8899)
Cloud agents (Operator etc.) fetch from OpenAI infra, NOT your localhost — expose this via a
tunnel (e.g. `ngrok http 8899`) or use a hosted webhook (webhook.site) as the collector and
point the payload at that public URL instead.
"""
import datetime
import http.server
import os
import socketserver

HOST = os.environ.get("COLLECTOR_HOST", "0.0.0.0")
PORT = int(os.environ.get("COLLECTOR_PORT", "8899"))
LOG = "collector.log"


class Handler(http.server.BaseHTTPRequestHandler):
    def _log(self, body=b""):
        ts = datetime.datetime.now().isoformat(timespec="seconds")
        ua = self.headers.get("User-Agent", "")
        host = self.headers.get("Host", "")
        line = f"[{ts}] {self.command} {self.path}  Host={host}  UA={ua!r}"
        print(line)
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            if body:
                f.write(f"    body: {body[:500]!r}\n")

    def do_GET(self):
        self._log()
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.end_headers()
        # 1x1 transparent GIF, so an <img> exfil renders cleanly
        self.wfile.write(
            b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!"
            b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00"
            b"\x00\x02\x02D\x01\x00;"
        )

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = 0
        self._log(self.rfile.read(n) if n else b"")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"[collector] http://{HOST}:{PORT}  (logging to {LOG})")
    with socketserver.TCPServer((HOST, PORT), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[collector] stopped")
