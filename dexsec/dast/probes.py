"""Safe, non-destructive proof-of-concept probe generators.

Hard rules for every payload in this module:
  * never mutate data (no DROP / DELETE / UPDATE / rm / shutdown)
  * never execute destructive shell commands
  * only observe: timing deltas, error messages, and reflected canaries
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass

from ..models import VulnClass

CANARY = "dexsec-canary-9f3a2b"


@dataclass
class Probe:
    """A single safe probe against one parameter."""

    vuln_class: VulnClass
    payload: str
    rationale: str
    expect: str  # "delay" | "error" | "canary" | "marker"


SQLI_TIMING_PAYLOADS = [
    "1' AND SLEEP(3) AND '1'='1",
    "1'; SELECT SLEEP(3); --",
    "1' OR SLEEP(3) -- ",
    "1' AND (SELECT SLEEP(3)) -- ",
]

SQLI_ERROR_PAYLOADS = [
    "'",
    "\"",
    "1' AND 1=CONVERT(int,(SELECT @@version))-- ",
    "1' UNION SELECT NULL,NULL-- ",
]

SQLI_BOOLEAN_PAYLOADS = [
    ("1' AND '1'='1", "1' AND '1'='2"),
]

CMD_INJECTION_PAYLOADS = [
    ("; echo dexsec-canary-9f3a2b", "cmd_echo"),
    ("| echo dexsec-canary-9f3a2b", "cmd_echo"),
    ("`echo dexsec-canary-9f3a2b`", "cmd_echo"),
    ("$(echo dexsec-canary-9f3a2b)", "cmd_echo"),
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "../../../../../../../../../../etc/hostname",
    "..\\..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini",
    "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cWindows%5cwin.ini",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1:1/dexsec-oast",
    "http://169.254.169.254/latest/meta-data/",
]

# Open redirect: a harmless, well-known destination that is never contacted.
REDIRECT_MARKER = "https://example.com/dexsec-redirect-probe"
REDIRECT_PAYLOADS = [
    REDIRECT_MARKER,
    f"//example.com/dexsec-redirect-probe",
    f"https://example.com/dexsec-redirect-probe?next=1",
]

# Server side template injection arithmetic canary.
SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "{{7*'7'}}"]

# NoSQL operator injection canaries.
NOSQL_PAYLOADS = [
    '{"$ne": null}',
    '{"$gt": ""}',
    '{"$regex": ".*"}',
]

# Security headers that a production API should send.
EXPECTED_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
]


def open_redirect_probes() -> list[Probe]:
    return [
        Probe(
            vuln_class=VulnClass.OPEN_REDIRECT,
            payload=p,
            rationale="Open redirect: the server is asked to redirect to a harmless marker URL.",
            expect="marker",
        )
        for p in REDIRECT_PAYLOADS
    ]


def template_injection_probes() -> list[Probe]:
    return [
        Probe(
            vuln_class=VulnClass.TEMPLATE_INJECTION,
            payload=p,
            rationale="SSTI: arithmetic expression that renders as 49 only if the template is evaluated.",
            expect="marker",
        )
        for p in SSTI_PAYLOADS
    ]


def nosql_probes() -> list[Probe]:
    return [
        Probe(
            vuln_class=VulnClass.NOSQL_INJECTION,
            payload=p,
            rationale="NoSQL operator injection: a comparison operator is sent as the value.",
            expect="marker",
        )
        for p in NOSQL_PAYLOADS
    ]


def craft_jwt_none_token(payload: str = '{"sub":"1","role":"admin"}') -> str:
    """Build a JWT whose header declares the 'none' algorithm.

    Used to check whether the server accepts unsigned tokens.  The token is
    never sent to a third party and grants no real access.
    """
    import base64
    import json

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    header = b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = b64(payload.encode())
    return f"{header}.{body}."


def sql_timing_probes() -> list[Probe]:
    return [
        Probe(
            vuln_class=VulnClass.SQL_INJECTION,
            payload=p,
            rationale="Time-based blind SQLi: observes a measurable response delay without changing data.",
            expect="delay",
        )
        for p in SQLI_TIMING_PAYLOADS
    ]


def sql_error_probes() -> list[Probe]:
    return [
        Probe(
            vuln_class=VulnClass.SQL_INJECTION,
            payload=p,
            rationale="Error-based SQLi: looks for a database error surfaced in the response body.",
            expect="error",
        )
        for p in SQLI_ERROR_PAYLOADS
    ]


def sql_boolean_pairs() -> list[tuple[Probe, Probe]]:
    pairs = []
    for true_p, false_p in SQLI_BOOLEAN_PAYLOADS:
        pairs.append(
            (
                Probe(VulnClass.SQL_INJECTION, true_p, "Boolean SQLi true condition.", "marker"),
                Probe(VulnClass.SQL_INJECTION, false_p, "Boolean SQLi false condition.", "marker"),
            )
        )
    return pairs


def command_injection_probes() -> list[Probe]:
    return [
        Probe(
            vuln_class=VulnClass.COMMAND_INJECTION,
            payload=p,
            rationale="Command injection: harmless echo canary; no file or process is modified.",
            expect="canary",
        )
        for p, _ in CMD_INJECTION_PAYLOADS
    ]


def path_traversal_probes() -> list[Probe]:
    return [
        Probe(
            vuln_class=VulnClass.PATH_TRAVERSAL,
            payload=p,
            rationale="Path traversal: reads a well-known non-sensitive OS file to prove traversal.",
            expect="marker",
        )
        for p in PATH_TRAVERSAL_PAYLOADS
    ]


def ssrf_probes() -> list[Probe]:
    return [
        Probe(
            vuln_class=VulnClass.SSRF,
            payload=p,
            rationale="SSRF: points the request at a non-routable local address; the request is only observed.",
            expect="marker",
        )
        for p in SSRF_PAYLOADS
    ]


def probes_for(vuln_class: VulnClass) -> list[Probe]:
    if vuln_class == VulnClass.SQL_INJECTION:
        return sql_timing_probes() + sql_error_probes()
    if vuln_class == VulnClass.COMMAND_INJECTION:
        return command_injection_probes()
    if vuln_class == VulnClass.PATH_TRAVERSAL:
        return path_traversal_probes()
    if vuln_class == VulnClass.SSRF:
        return ssrf_probes()
    if vuln_class == VulnClass.OPEN_REDIRECT:
        return open_redirect_probes()
    if vuln_class == VulnClass.TEMPLATE_INJECTION:
        return template_injection_probes()
    if vuln_class == VulnClass.NOSQL_INJECTION:
        return nosql_probes()
    return []


def build_url(base: str, path: str, method: str, param: str, payload: str) -> str:
    """Build a probe URL, sending the payload in the right place per method."""
    url = base.rstrip("/") + path if path.startswith("/") else f"{base.rstrip('/')}/{path}"
    if method.upper() in ("GET", "DELETE", "HEAD"):
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{urllib.parse.quote(param, safe='')}={urllib.parse.quote(payload, safe='')}"
    return url


def build_curl(method: str, url: str, param: str, payload: str, body_mode: str = "query") -> str:
    quoted = urllib.parse.quote(payload, safe="")
    if method.upper() in ("GET", "DELETE", "HEAD"):
        return f"curl -i -X {method.upper()} '{url}'"
    if body_mode == "json":
        return (
            f"curl -i -X {method.upper()} '{url}' \\\n"
            f"  -H 'Content-Type: application/json' \\\n"
            f"  -d '{{\"{param}\": \"{payload}\"}}'"
        )
    return (
        f"curl -i -X {method.upper()} '{url}' \\\n"
        f"  -H 'Content-Type: application/x-www-form-urlencoded' \\\n"
        f"  --data '{param}={quoted}'"
    )
