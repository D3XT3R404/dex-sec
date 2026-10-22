"""Intentionally vulnerable demo app used for DEX-SEC end-to-end validation.

DO NOT DEPLOY.  It contains three classic sinks (SQLi, command injection,
path traversal) so the scanner and safe verifier can be exercised locally.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import xml.dom.minidom
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import requests


class Router:
    """Minimal declarative route registry (mirrors Flask/FastAPI decorators)."""

    def __init__(self) -> None:
        self.routes: dict[str, tuple[str, tuple[str, ...]]] = {}

    def route(self, path: str, methods: tuple[str, ...] = ("GET",)):
        def decorator(func):
            self.routes[path] = (func.__name__, methods)
            return func
        return decorator


router = Router()


class VulnerableHandler(BaseHTTPRequestHandler):
    server_version = "DEX-SECDemo/1.0"

    def log_message(self, fmt, *args):  # keep test output quiet
        pass

    def _send(self, body: str, status: int = 200) -> None:
        data = body.encode("utf-8", errors="replace")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        q = params.get("q", [""])[0]
        host = params.get("host", [""])[0]
        name = params.get("name", [""])[0]

        if parsed.path == "/health":
            return self._send("ok")
        if parsed.path == "/search":
            return self._search(q)
        if parsed.path == "/ping":
            return self._ping(host)
        if parsed.path == "/file":
            return self._file(name)
        if parsed.path == "/goto":
            return self._goto(params.get("next", [""])[0])
        if parsed.path == "/greet":
            return self._greet(params.get("name", [""])[0])
        if parsed.path == "/invoice":
            return self._invoice(params.get("invoice_id", [""])[0])
        if parsed.path == "/profile":
            return self._profile(params.get("uid", [""])[0])
        if parsed.path == "/fetch":
            return self._fetch(params.get("url", [""])[0])
        if parsed.path == "/xml":
            return self._xml()
        if parsed.path == "/missing":
            return self._missing(params.get("ref", [""])[0])
        return self._send("not found", 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/xml":
            return self._xml()
        return self._send("not found", 404)

    @router.route("/missing", methods=("GET",))
    def _missing(self, ref: str):
        # Unhandled exception with a debug page -> 5xx + stack trace (fuzzing target).
        try:
            raise ValueError(f"unknown reference: {ref}")
        except Exception:
            import traceback
            return self._send(traceback.format_exc(), 500)

    @router.route("/search", methods=("GET",))
    def _search(self, q: str):
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE users (id INTEGER, name TEXT)")
        conn.executemany("INSERT INTO users VALUES (?, ?)", [(1, "alice"), (2, "bob")])
        try:
            query = f"SELECT id, name FROM users WHERE name = '{q}'"
            rows = conn.execute(query).fetchall()
            return self._send(f"query: {query}\nrows: {rows}")
        except Exception as exc:
            return self._send(f"sqlite3.OperationalError: {exc}", 500)

    @router.route("/ping", methods=("GET",))
    def _ping(self, host: str):
        command = f"echo {host}"
        try:
            proc = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
            return self._send(proc.stdout + proc.stderr)
        except Exception as exc:
            return self._send(f"command failed: {exc}", 500)

    @router.route("/file", methods=("GET",))
    def _file(self, name: str):
        try:
            with open(name, "r", encoding="utf-8", errors="replace") as handle:
                return self._send(handle.read()[:4000])
        except Exception as exc:
            return self._send(f"file error: {exc}", 404)

    @router.route("/invoice", methods=("GET",))
    def _invoice(self, invoice_id: str):
        # No access scoping at all: classic IDOR / BOLA.
        return self._send(f"invoice {invoice_id}: total 4200 EUR, client=acme-corp")

    @router.route("/goto", methods=("GET",))
    def _goto(self, next: str):
        self.send_response(302)
        self.send_header("Location", next)
        self.send_header("Content-Length", "0")
        self.end_headers()

    @router.route("/greet", methods=("GET",))
    def _greet(self, name: str):
        return self._send(f"hello {name}")

    @router.route("/profile", methods=("GET",))
    def _profile(self, uid: str):
        # Role check only, no per-record scoping -> still an IDOR candidate.
        if not self.headers.get("X-Api-Key"):
            return self._send("unauthorized", 401)
        return self._send(f"profile of user {uid}")

    @router.route("/fetch", methods=("GET",))
    def _fetch(self, url: str):
        # SSRF: the server fetches an arbitrary URL supplied by the client.
        try:
            response = requests.get(url, timeout=5)
            return self._send(response.text[:2000])
        except Exception as exc:
            return self._send(f"fetch error: {exc}", 500)

    @router.route("/xml", methods=("POST",))
    def _xml(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        try:
            # XXE: the XML parser resolves external entities.
            document = xml.dom.minidom.parseString(body)
            return self._send(document.toxml()[:2000])
        except Exception as exc:
            return self._send(f"xml error: {exc}", 400)


def serve(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), VulnerableHandler)


if __name__ == "__main__":
    bound_port = int(os.getenv("DEXSEC_DEMO_PORT", "8765"))
    srv = serve(port=bound_port)
    print(f"DEX-SEC vulnerable demo listening on http://127.0.0.1:{bound_port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
