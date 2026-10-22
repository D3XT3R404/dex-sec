"""Schema driven black-box API fuzzing.

The OpenAPI/Swagger document is used as a map of the API: which paths exist,
which parameters they take and which methods they accept.  Each parameter is
then probed with a small set of *safe* values and the responses are inspected
for anomalies (stack traces, unexpected 5xx, reflected input, slow responses).

Safety rules
------------
* only idempotent methods (GET/HEAD/OPTIONS) are used unless the caller
  explicitly allows more;
* every request is rate limited;
* the total number of requests is capped;
* payloads are read-only markers, never destructive statements;
* an allow-list can restrict which paths may be touched.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

import requests

from ..models import Severity, VulnClass

SAFE_MARKERS = "dexsec-probe-7c1f"
IDEMPOTENT_METHODS = {"GET", "HEAD", "OPTIONS"}
STACK_TRACE_RE = re.compile(
    r"Traceback \(most recent call last\)|"
    r"java\.lang\.[A-Za-z]+Exception|"
    r"at [A-Za-z0-9_.$]+\([A-Za-z0-9_.$]+\.java:\d+\)|"
    r"Microsoft \.NET Framework|System\.[A-Za-z]+Exception|"
    r"goroutine \d+ \[running\]|"
    r"django\.core\.exceptions|"
    r"werkzeug\.exceptions|"
    r"SQLSTATE\[|"
    r"ORA-\d{5}|"
    r"node_modules[\\/]|"
    r"/[A-Za-z]:\\[^\s\"']+|[A-Za-z]:\\[^\s\"']+\.py|"
    r"\.py\", line \d+",
    re.IGNORECASE,
)
SQL_ERROR_RE = re.compile(
    r"sql syntax|mysql_fetch|pg_query|pq::|sqlite3?\.OperationalError|"
    r"ORA-\d{5}|unclosed quotation mark|syntax error at or near|"
    r"jdbc\.sql|SQLException|sequelize.*error|pymysql",
    re.IGNORECASE,
)

# Safe payload values, grouped by what they try to trigger.
PAYLOADS: list[tuple[str, str, str]] = [
    ("quote", "'", "mencoba memicu error SQL dengan satu kutip"),
    ("double_quote", '"', "mencoba memicu error parsing dengan dua kutip"),
    ("ssti", "{{7*7}}", "mencoba mendeteksi server side template injection"),
    ("traversal", "../../../../etc/passwd", "mencoba memicu path traversal"),
    ("long", "A" * 512, "mencoba memicu buffer/validation error"),
    ("unicode", "\u00e9\u00e8\u00ea" * 8, "mencoba memicu error encoding"),
    ("marker", SAFE_MARKERS, "marker refleksi (mengecek echo tanpa injeksi)"),
]


@dataclass
class FuzzFinding:
    method: str
    path: str
    parameter: str
    kind: str
    payload: str
    status_code: int
    detail: str
    severity: str = "MEDIUM"
    response_excerpt: str = ""
    request_example: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "parameter": self.parameter,
            "kind": self.kind,
            "payload": self.payload,
            "status_code": self.status_code,
            "detail": self.detail,
            "severity": self.severity,
            "response_excerpt": self.response_excerpt,
            "request_example": self.request_example,
        }


@dataclass
class FuzzConfig:
    spec_path: str = ""
    target: str = ""
    allowed_methods: set[str] = field(default_factory=lambda: set(IDEMPOTENT_METHODS))
    allowed_paths: list[str] = field(default_factory=list)  # empty = all
    max_requests: int = 200
    rate_limit: float = 0.2  # seconds between requests
    timeout: float = 8.0
    include_body: bool = False


def load_spec(spec_path: str) -> dict[str, Any]:
    """Load an OpenAPI/Swagger document (JSON or YAML)."""
    with open(spec_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    if spec_path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("PyYAML is required to read YAML specs (pip install pyyaml)") from exc
        return yaml.safe_load(content) or {}
    return json.loads(content)


def _parameters(operation: dict[str, Any], path_item: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Return (name, location, required) tuples for one operation."""
    result: list[tuple[str, str, str]] = []
    sources: list[list[Any]] = []
    for group in (operation.get("parameters"), path_item.get("parameters")):
        if isinstance(group, list):
            sources.append(group)
    for group in sources:
        for source in group:
            if not isinstance(source, dict):
                continue
            name = source.get("name")
            location = source.get("in", "query")
            required = "true" if source.get("required") else "false"
            if name:
                result.append((str(name), str(location), required))
    body = operation.get("requestBody") or {}
    content = body.get("content") or {}
    for media in content.values():
        schema = (media or {}).get("schema") or {}
        properties = schema.get("properties") or {}
        for name, definition in properties.items():
            result.append((str(name), "body", "false"))
        if schema.get("type") == "array" and schema.get("items"):
            items = schema["items"]
            for name in (items.get("properties") or {}):
                result.append((str(name), "body", "false"))
    return result


def iter_operations(spec: dict[str, Any]) -> Iterable[tuple[str, str, dict[str, Any], dict[str, Any]]]:
    """Yield (method, path, operation, path_item) for every operation."""
    for path, path_item in (spec.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        shared = path_item.get("parameters") or []
        for method, operation in path_item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                continue
            if not isinstance(operation, dict):
                continue
            yield method.upper(), path, operation, {"parameters": shared}


class OpenApiFuzzer:
    """Executes a bounded, rate limited fuzz run against the target."""

    def __init__(self, config: FuzzConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "DEX-SEC/0.2 (authorized security testing)"})
        self.requests_sent = 0
        self.findings: list[FuzzFinding] = []

    # ------------------------------------------------------------- helpers
    def _path_allowed(self, path: str) -> bool:
        if not self.config.allowed_paths:
            return True
        return any(path.startswith(prefix) for prefix in self.config.allowed_paths)

    def _budget_left(self) -> bool:
        return self.requests_sent < self.config.max_requests

    def _sleep(self) -> None:
        if self.config.rate_limit > 0:
            time.sleep(self.config.rate_limit)

    def _send(self, method: str, path: str, params: dict[str, Any], json_body: Optional[dict]) -> Optional[requests.Response]:
        if not self._budget_left():
            return None
        url = self.config.target.rstrip("/") + path
        try:
            if method in IDEMPOTENT_METHODS:
                response = self.session.get(url, params=params, timeout=self.config.timeout, allow_redirects=False)
            else:
                response = self.session.request(
                    method, url, params=params, json=json_body, timeout=self.config.timeout, allow_redirects=False
                )
        except requests.RequestException:
            self.requests_sent += 1
            return None
        self.requests_sent += 1
        self._sleep()
        return response

    def _record(self, method: str, path: str, parameter: str, kind: str, payload: str,
                response: requests.Response, detail: str, severity: str) -> None:
        body = response.text or ""
        url = self.config.target.rstrip("/") + path
        if parameter and method in IDEMPOTENT_METHODS:
            url = f"{url}?{parameter}={payload}"
        example = f"curl -i -X {method} '{url}'"
        self.findings.append(
            FuzzFinding(
                method=method,
                path=path,
                parameter=parameter,
                kind=kind,
                payload=payload,
                status_code=response.status_code,
                detail=detail,
                severity=severity,
                response_excerpt=re.sub(r"\s+", " ", body)[:300],
                request_example=example,
            )
        )

    # ---------------------------------------------------------------- main
    def run(self, spec: dict[str, Any]) -> list[FuzzFinding]:
        for method, path, operation, path_item in iter_operations(spec):
            if method not in self.config.allowed_methods:
                continue
            if not self._path_allowed(path):
                continue
            parameters = _parameters(operation, path_item)
            if not parameters:
                continue
            baseline = self._send(method, path, {}, None)
            baseline_code = baseline.status_code if baseline is not None else None
            baseline_len = len(baseline.text or "") if baseline is not None else 0

            for name, location, _required in parameters:
                if not self._budget_left():
                    break
                for kind, payload, purpose in PAYLOADS:
                    if not self._budget_left():
                        break
                    if location == "body" and not self.config.include_body:
                        continue
                    if location == "body":
                        response = self._send(method, path, {}, {name: payload})
                    else:
                        response = self._send(method, path, {name: payload}, None)
                    if response is None:
                        continue
                    self._inspect(method, path, name, kind, payload, purpose, response, baseline_code, baseline_len)
        return self.findings

    def _inspect(self, method: str, path: str, parameter: str, kind: str, payload: str, purpose: str,
                 response: requests.Response, baseline_code: Optional[int], baseline_len: int) -> None:
        body = response.text or ""
        code = response.status_code

        if code >= 500 and (baseline_code is None or baseline_code < 500):
            self._record(method, path, parameter, "unhandled_exception", payload, response,
                         f"Server error 5xx muncul setelah probe {purpose}.", "HIGH")
            return
        if STACK_TRACE_RE.search(body) and (baseline_code is None or not STACK_TRACE_RE.search("")):
            self._record(method, path, parameter, "stack_trace", payload, response,
                         "Respons memuat stack trace / path internal server.", "HIGH")
            return
        if SQL_ERROR_RE.search(body):
            self._record(method, path, parameter, "sql_error", payload, response,
                         "Respons memuat pesan error database.", "HIGH")
            return
        if kind == "ssti" and "49" in body and payload.split("7")[0] in body:
            self._record(method, path, parameter, "ssti", payload, response,
                         "Ekspresi template dieksekusi (7*7 -> 49): template injection.", "CRITICAL")
            return
        if kind == "traversal" and ("root:" in body or "[extensions]" in body):
            self._record(method, path, parameter, "path_traversal", payload, response,
                         "Respons memuat isi file di luar direktori aplikasi.", "CRITICAL")
            return
        if kind == "marker" and SAFE_MARKERS in body:
            self._record(method, path, parameter, "reflected_input", payload, response,
                         "Input pengguna dikembalikan apa adanya (refleksi tanpa escaping).", "LOW")
            return
        if baseline_len and abs(len(body) - baseline_len) > max(400, baseline_len // 2):
            self._record(method, path, parameter, "response_anomaly", payload, response,
                         f"Panjang respons berubah drastis ({baseline_len} -> {len(body)}).", "INFO")


def run_fuzz(config: FuzzConfig) -> tuple[list[FuzzFinding], int]:
    """Run a fuzz session and return (findings, requests_sent)."""
    spec = load_spec(config.spec_path)
    fuzzer = OpenApiFuzzer(config)
    findings = fuzzer.run(spec)
    return findings, fuzzer.requests_sent
