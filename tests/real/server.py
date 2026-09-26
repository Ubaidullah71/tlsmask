"""A tiny local HTTP/1.1 server for real-library tests: it reports what arrived, in wire order."""

from __future__ import annotations

import base64
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):  # a client that timed out and left
        pass


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, status, body=b"", headers=()):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _route(self):
        parts = urlsplit(self.path)
        query = parse_qs(parts.query)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if parts.path == "/echo":
            report = {
                "method": self.command,
                "path": self.path,
                "headers": [[name, value] for name, value in self.headers.items()],
                "body": base64.b64encode(body).decode(),
            }
            self._send(200, json.dumps(report).encode(), [("Content-Type", "application/json")])
        elif parts.path == "/bytes":
            self._send(200, bytes(range(256)), [("Content-Type", "image/png")])
        elif parts.path == "/set":
            self._send(
                200, b"ok", [("Set-Cookie", f"{k}={v[0]}; Path=/") for k, v in query.items()]
            )
        elif parts.path == "/redirect":
            headers = [("Location", query.get("to", ["/echo"])[0])]
            headers += [("Set-Cookie", cookie) for cookie in query.get("cookie", [])]
            self._send(int(query.get("status", ["302"])[0]), b"", headers)
        elif parts.path == "/empty-br":
            # like a real server: brotli only when the client offers it
            offered = self.headers.get("Accept-Encoding") or ""
            encoding = [("Content-Encoding", "br")] if "br" in offered else []
            self._send(int(query.get("status", ["200"])[0]), b"", encoding)
        elif parts.path == "/slow":
            time.sleep(float(query.get("s", ["3"])[0]))
            self._send(200, b"late")
        else:
            self._send(404, b"nope")

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = _route
