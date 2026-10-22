"""Local out-of-band (OAST) callback listener.

A tiny HTTP server that listens on 127.0.0.1 and records every request it
receives.  It is used to *prove* that the target really performed an outbound
request (SSRF, XXE, blind command execution) instead of merely reflecting
the payload.

Everything stays on the loopback interface: no external service, no API key,
no traffic leaving the machine.
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


@dataclass
class OastHit:
    path: str
    timestamp: float
    headers: dict[str, str] = field(default_factory=dict)


class _Handler(BaseHTTPRequestHandler):
    listener: "OastListener"

    def _record(self) -> None:
        parsed = urlparse(self.path)
        self.listener.hits.append(
            OastHit(
                path=parsed.path,
                timestamp=time.time(),
                headers={k.lower(): v for k, v in self.headers.items()},
            )
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = _record
    do_POST = _record
    do_HEAD = _record

    def log_message(self, fmt, *args):  # silence the default stderr logging
        return


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class OastListener:
    """Context manager that exposes a callback URL and collects the hits."""

    def __init__(self, token: str = "dexsec"):
        self.token = token
        self.port = _free_port()
        self.hits: list[OastHit] = []
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # ---------------------------------------------------------------- setup
    def start(self) -> "OastListener":
        handler = type("BoundHandler", (_Handler,), {"listener": self})
        self._server = ThreadingHTTPServer(("127.0.0.1", self.port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def __enter__(self) -> "OastListener":
        return self.start()

    def __exit__(self, *exc_info) -> None:
        self.close()

    # ---------------------------------------------------------------- usage
    def url(self, kind: str = "probe") -> str:
        """Callback URL that is unique per probe kind."""
        return f"http://127.0.0.1:{self.port}/{self.token}-{kind}"

    def waited_for(self, kind: str = "probe", timeout: float = 3.0) -> OastHit | None:
        """Wait until a callback of the given kind arrives."""
        needle = f"/{self.token}-{kind}"
        deadline = time.time() + timeout
        while time.time() < deadline:
            for hit in list(self.hits):
                if needle in hit.path:
                    return hit
            time.sleep(0.1)
        return None
