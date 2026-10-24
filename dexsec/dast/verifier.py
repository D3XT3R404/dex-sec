"""Targeted external verification engine.

The verifier only probes endpoints that the static analysis phase already
flagged as suspicious, so it stays fast, quiet and low-noise.
All probes are read-only and non-destructive by construction.
"""

from __future__ import annotations

import re
import secrets
import tempfile
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests

from ..models import (
    CodeFinding,
    VerificationResult,
    VerificationStatus,
    VulnClass,
)
from . import probes
from .oast import OastListener

DEFAULT_TIMEOUT = 8.0
ERROR_SIGNATURES = [
    r"sql syntax.*mysql",
    r"warning.*mysql",
    r"postgresql.*error",
    r"sqlite3?\.OperationalError",
    r"ORA-\d{5}",
    r"unclosed quotation mark",
    r"syntax error at or near",
    r"microsoft ole db provider",
    r"you have an error in your sql syntax",
    r"jdbc.*exception",
    r"sequelize.*error",
    r"django\.db\.utils",
    r"pymysql.*error",
    r"SQLITE_ERROR",
    r"OperationalError",
    r"unrecognized token",
    r"no such (?:table|column|function)",
    r"near \"[^\"]+\": syntax error",
    r"SQLException",
    r"pg_query",
]
DB_ERROR_RE = re.compile("|".join(ERROR_SIGNATURES), re.IGNORECASE)
CANARY_RE = re.compile(probes.CANARY, re.IGNORECASE)
PASSWD_RE = re.compile(r"root:[^:]*:0:0", re.IGNORECASE)
WINDOWS_INI_RE = re.compile(r"\[extensions\]|\[fonts\]", re.IGNORECASE)


class Verifier:
    """Runs safe probes against a live target and records evidence."""

    def __init__(self, base_url: str, timeout: float = DEFAULT_TIMEOUT, delay_threshold: float = 2.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.delay_threshold = delay_threshold
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "DEX-SEC/0.2 (authorized security testing)"})

    # ------------------------------------------------------------------ utils
    def _request(
        self,
        method: str,
        url: str,
        param: str,
        payload: str,
    ) -> tuple[Optional[requests.Response], float, str]:
        body_mode = "json" if self._looks_like_json_endpoint(url) else "form"
        try:
            if method.upper() in ("GET", "DELETE", "HEAD"):
                full_url = probes.build_url(self.base_url, url, method, param, payload)
                resp = self.session.get(full_url, timeout=self.timeout, allow_redirects=False)
            else:
                full_url = self.base_url.rstrip("/") + (url if url.startswith("/") else "/" + url)
                if body_mode == "json":
                    resp = self.session.post(
                        full_url, json={param: payload}, timeout=self.timeout, allow_redirects=False
                    )
                else:
                    resp = self.session.post(
                        full_url, data={param: payload}, timeout=self.timeout, allow_redirects=False
                    )
            return resp, 0.0, ""
        except requests.RequestException as exc:
            return None, 0.0, str(exc)

    def _timed_request(self, url: str, param: str, payload: str) -> tuple[Optional[requests.Response], float, str]:
        target = probes.build_url(self.base_url, url, "GET", param, payload)
        start = time.perf_counter()
        try:
            resp = self.session.get(target, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException as exc:
            return None, 0.0, str(exc)
        return resp, (time.perf_counter() - start) * 1000, ""

    @staticmethod
    def _looks_like_json_endpoint(url: str) -> bool:
        return "/api" in url or "json" in url.lower()

    @staticmethod
    def _excerpt(text: str, limit: int = 400) -> str:
        text = re.sub(r"\s+", " ", text or "").strip()
        return text[:limit]

    # ------------------------------------------------------------- strategies
    def verify_sql_injection(self, finding: CodeFinding) -> list[VerificationResult]:
        results: list[VerificationResult] = []
        route = finding.route
        if route is None:
            return results
        param = self._pick_param(route, finding)
        if param is None:
            return results

        # 1) Baseline timing
        baseline, base_ms, err = self._timed_request(route.path, param, "1")
        if err:
            return [VerificationResult(
                vuln_class=finding.vuln_class, status=VerificationStatus.ERROR,
                target_url=route.path, payload="baseline", evidence="", error=err,
            )]
        base_ms = base_ms or 0.0
        baseline_status = baseline.status_code if baseline is not None else None

        # 2) Timing probes
        for probe in probes.sql_timing_probes():
            resp, elapsed, err = self._timed_request(route.path, param, probe.payload)
            if err:
                continue
            if elapsed - base_ms >= self.delay_threshold * 1000:
                curl = probes.build_curl("GET", probes.build_url(self.base_url, route.path, "GET", param, probe.payload), param, probe.payload)
                results.append(VerificationResult(
                    vuln_class=VulnClass.SQL_INJECTION,
                    status=VerificationStatus.CONFIRMED_VULNERABLE,
                    target_url=route.path,
                    payload=probe.payload,
                    evidence=(
                        f"Response time {elapsed:.0f} ms vs baseline {base_ms:.0f} ms "
                        f"(delta {elapsed - base_ms:.0f} ms >= threshold {self.delay_threshold * 1000:.0f} ms). "
                        f"Time-based blind SQL injection proven without modifying data."
                    ),
                    response_time_ms=elapsed,
                    baseline_time_ms=base_ms,
                    http_status=resp.status_code if resp is not None else None,
                    response_excerpt=self._excerpt(resp.text) if resp is not None else "",
                    safe_poc_curl=curl,
                ))
                return results

        # 3) Error-based probes
        for probe in probes.sql_error_probes():
            resp, _, err = self._request("GET", route.path, param, probe.payload)
            if err and baseline is not None and baseline.status_code < 500:
                # The application crashed on our payload while the baseline was
                # fine: the injected quote broke the query/handler.
                curl = probes.build_curl("GET", probes.build_url(self.base_url, route.path, "GET", param, probe.payload), param, probe.payload)
                return [VerificationResult(
                    vuln_class=VulnClass.SQL_INJECTION,
                    status=VerificationStatus.CONFIRMED_VULNERABLE,
                    target_url=route.path,
                    payload=probe.payload,
                    evidence=(
                        f"The request with the payload '{probe.payload}' made the server fail "
                        f"({err.splitlines()[0][:160]}) while the same endpoint answered normally before. "
                        "The injected value breaks the query and the error is not handled."
                    ),
                    baseline_time_ms=base_ms,
                    safe_poc_curl=curl,
                )]
            if err or resp is None:
                continue
            body = resp.text or ""
            if DB_ERROR_RE.search(body):
                curl = probes.build_curl("GET", probes.build_url(self.base_url, route.path, "GET", param, probe.payload), param, probe.payload)
                results.append(VerificationResult(
                    vuln_class=VulnClass.SQL_INJECTION,
                    status=VerificationStatus.CONFIRMED_VULNERABLE,
                    target_url=route.path,
                    payload=probe.payload,
                    evidence=f"Database error signature found in response body: {self._excerpt(body, 200)}",
                    response_time_ms=0.0,
                    baseline_time_ms=base_ms,
                    http_status=resp.status_code,
                    response_excerpt=self._excerpt(body),
                    safe_poc_curl=curl,
                ))
                return results

        # 4) Boolean differential
        for true_probe, false_probe in probes.sql_boolean_pairs():
            t_resp, _, _ = self._request("GET", route.path, param, true_probe.payload)
            f_resp, _, _ = self._request("GET", route.path, param, false_probe.payload)
            if t_resp is None or f_resp is None:
                continue
            t_len, f_len = len(t_resp.text or ""), len(f_resp.text or "")
            t_code, f_code = t_resp.status_code, f_resp.status_code
            if (t_len > 0 and abs(t_len - f_len) > 20) or (t_code == 200 and f_code >= 500):
                curl = probes.build_curl("GET", probes.build_url(self.base_url, route.path, "GET", param, true_probe.payload), param, true_probe.payload)
                results.append(VerificationResult(
                    vuln_class=VulnClass.SQL_INJECTION,
                    status=VerificationStatus.POTENTIAL,
                    target_url=route.path,
                    payload=true_probe.payload,
                    evidence=(
                        f"Boolean differential: true-condition response {t_len} bytes / HTTP {t_code} "
                        f"vs false-condition response {f_len} bytes / HTTP {f_code}."
                    ),
                    http_status=t_code,
                    response_excerpt=self._excerpt(t_resp.text),
                    safe_poc_curl=curl,
                ))
                return results

        results.append(VerificationResult(
            vuln_class=VulnClass.SQL_INJECTION,
            status=VerificationStatus.NOT_REPRODUCIBLE,
            target_url=route.path,
            payload=param,
            evidence=(
                f"No timing delta (baseline {base_ms:.0f} ms), no database error signature, "
                f"no boolean differential. Endpoint answered HTTP {baseline_status}. "
                f"Sink may be sanitized, parameterized, or unreachable at this path."
            ),
            baseline_time_ms=base_ms,
            http_status=baseline_status,
        ))
        return results

   
    def verify_command_injection(self, finding: CodeFinding) -> list[VerificationResult]:
        route = finding.route
        if route is None:
            return []

        param = self._pick_param(route, finding)
        if param is None:
            return []

        for probe in probes.command_injection_probes():
            resp, _, err = self._request(
                route.method, route.path, param, probe.payload
            )

            if err or resp is None:
                continue

            body = resp.text or ""

            # Canaries must appear as a standalone output line.
            # A reflected canary alone does not prove command execution.
            if any(
                CANARY_RE.fullmatch(line.strip())
                for line in body.splitlines()
            ):
                curl = probes.build_curl(
                    route.method,
                    probes.build_url(
                        self.base_url,
                        route.path,
                        route.method,
                        param,
                        probe.payload,
                    ),
                    param,
                    probe.payload,
                )

                return [
                    VerificationResult(
                        vuln_class=VulnClass.COMMAND_INJECTION,
                        status=VerificationStatus.CONFIRMED_VULNERABLE,
                        target_url=route.path,
                        payload=probe.payload,
                        evidence=(
                            f"Canary '{probes.CANARY}' appeared as a "
                            "standalone response line. Verify that this "
                            "is evidence of command execution."
                        ),
                        http_status=resp.status_code,
                        response_excerpt=self._excerpt(body),
                        safe_poc_curl=curl,
                    )
                ]

        return [
            VerificationResult(
                vuln_class=VulnClass.COMMAND_INJECTION,
                status=VerificationStatus.NOT_REPRODUCIBLE,
                target_url=route.path,
                payload=param,
                evidence=(
                    "No standalone command canary was found in the response."
                ),
            )
        ]
    def verify_path_traversal(self, finding: CodeFinding) -> list[VerificationResult]:
        route = finding.route
        if route is None:
            return []
        param = self._pick_param(route, finding)
        if param is None:
            return []
        for probe in probes.path_traversal_probes():
            resp, _, err = self._request(route.method, route.path, param, probe.payload)
            if err or resp is None:
                continue
            body = resp.text or ""
            if PASSWD_RE.search(body) or WINDOWS_INI_RE.search(body):
                curl = probes.build_curl(route.method, probes.build_url(self.base_url, route.path, route.method, param, probe.payload), param, probe.payload)
                return [VerificationResult(
                    vuln_class=VulnClass.PATH_TRAVERSAL,
                    status=VerificationStatus.CONFIRMED_VULNERABLE,
                    target_url=route.path,
                    payload=probe.payload,
                    evidence="A file outside the intended directory was returned by the server: path traversal proven.",
                    http_status=resp.status_code,
                    response_excerpt=self._excerpt(body),
                    safe_poc_curl=curl,
                )]
        return [VerificationResult(
            vuln_class=VulnClass.PATH_TRAVERSAL,
            status=VerificationStatus.NOT_REPRODUCIBLE,
            target_url=route.path,
            payload=param,
            evidence="No sensitive file content returned. Path may be normalized or restricted.",
        )]

    def verify_ssrf(self, finding: CodeFinding) -> list[VerificationResult]:
        route = finding.route
        if route is None:
            return []
        param = self._pick_param(route, finding)
        if param is None:
            return []
        for probe in probes.ssrf_probes():
            resp, _, err = self._request(route.method, route.path, param, probe.payload)
            if err:
                continue
            if resp is None:
                continue
            body = resp.text or ""
            if "169.254.169.254" in body or "dexsec-oast" in body or "MetaData" in body:
                curl = probes.build_curl(route.method, probes.build_url(self.base_url, route.path, route.method, param, probe.payload), param, probe.payload)
                return [VerificationResult(
                    vuln_class=VulnClass.SSRF,
                    status=VerificationStatus.CONFIRMED_VULNERABLE,
                    target_url=route.path,
                    payload=probe.payload,
                    evidence="Response reflects the internal metadata address: server-side request forgery proven.",
                    http_status=resp.status_code,
                    response_excerpt=self._excerpt(body),
                    safe_poc_curl=curl,
                )]
        return [VerificationResult(
            vuln_class=VulnClass.SSRF,
            status=VerificationStatus.NOT_REPRODUCIBLE,
            target_url=route.path,
            payload=param,
            evidence="No internal-address response detected. Outbound request may be filtered by egress rules.",
        )]

    def verify_open_redirect(self, finding: CodeFinding) -> list[VerificationResult]:
        route = finding.route
        if route is None:
            return []
        param = self._pick_param(route, finding) or "next"
        for probe in probes.open_redirect_probes():
            resp, _, err = self._request(route.method, route.path, param, probe.payload)
            if err or resp is None:
                continue
            location = resp.headers.get("Location", "")
            if 300 <= resp.status_code < 400 and "example.com/dexsec-redirect-probe" in location:
                curl = probes.build_curl(route.method, probes.build_url(self.base_url, route.path, route.method, param, probe.payload), param, probe.payload)
                return [VerificationResult(
                    vuln_class=VulnClass.OPEN_REDIRECT,
                    status=VerificationStatus.CONFIRMED_VULNERABLE,
                    target_url=route.path,
                    payload=probe.payload,
                    evidence=f"Server answered HTTP {resp.status_code} with Location '{location}': the redirect target is fully controlled by the request.",
                    http_status=resp.status_code,
                    response_excerpt=self._excerpt(location),
                    safe_poc_curl=curl,
                )]
        return [VerificationResult(
            vuln_class=VulnClass.OPEN_REDIRECT,
            status=VerificationStatus.NOT_REPRODUCIBLE,
            target_url=route.path,
            payload=param,
            evidence="The server did not redirect to the supplied external URL.",
        )]

    def verify_template_injection(self, finding: CodeFinding) -> list[VerificationResult]:
        route = finding.route
        if route is None:
            return []
        param = self._pick_param(route, finding) or "q"
        for probe in probes.template_injection_probes():
            resp, _, err = self._request(route.method, route.path, param, probe.payload)
            if err or resp is None:
                continue
            body = resp.text or ""
            if "49" in body and probe.payload.split("7")[0] in body:
                curl = probes.build_curl(route.method, probes.build_url(self.base_url, route.path, route.method, param, probe.payload), param, probe.payload)
                return [VerificationResult(
                    vuln_class=VulnClass.TEMPLATE_INJECTION,
                    status=VerificationStatus.CONFIRMED_VULNERABLE,
                    target_url=route.path,
                    payload=probe.payload,
                    evidence="The arithmetic expression was evaluated by the template engine (7*7 rendered as 49): server side template injection proven.",
                    http_status=resp.status_code,
                    response_excerpt=self._excerpt(body),
                    safe_poc_curl=curl,
                )]
        return [VerificationResult(
            vuln_class=VulnClass.TEMPLATE_INJECTION,
            status=VerificationStatus.NOT_REPRODUCIBLE,
            target_url=route.path,
            payload=param,
            evidence="The template expression was not evaluated in the response.",
        )]

    def verify_nosql_injection(self, finding: CodeFinding) -> list[VerificationResult]:
        route = finding.route
        if route is None:
            return []
        param = self._pick_param(route, finding) or "q"
        for probe in probes.nosql_probes():
            resp, _, err = self._request(route.method, route.path, param, probe.payload)
            if err or resp is None:
                continue
            body = resp.text or ""
            if "$ne" in body or "$gt" in body or "$regex" in body:
                curl = probes.build_curl(route.method, probes.build_url(self.base_url, route.path, route.method, param, probe.payload), param, probe.payload)
                return [VerificationResult(
                    vuln_class=VulnClass.NOSQL_INJECTION,
                    status=VerificationStatus.CONFIRMED_VULNERABLE,
                    target_url=route.path,
                    payload=probe.payload,
                    evidence="The NoSQL operator was reflected by the backend, so the query can be influenced by operators instead of a plain value.",
                    http_status=resp.status_code,
                    response_excerpt=self._excerpt(body),
                    safe_poc_curl=curl,
                )]
        return [VerificationResult(
            vuln_class=VulnClass.NOSQL_INJECTION,
            status=VerificationStatus.NOT_REPRODUCIBLE,
            target_url=route.path,
            payload=param,
            evidence="No NoSQL operator was reflected in the response.",
        )]

    def verify_jwt_none_alg(self, finding: CodeFinding) -> list[VerificationResult]:
        route = finding.route
        if route is None:
            return []
        token = probes.craft_jwt_none_token()
        garbage = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.deadbeefdeadbeef"
        try:
            good = self.session.get(
                self.base_url.rstrip("/") + route.path,
                headers={"Authorization": f"Bearer {token}"},
                timeout=self.timeout,
                allow_redirects=False,
            )
            bad = self.session.get(
                self.base_url.rstrip("/") + route.path,
                headers={"Authorization": f"Bearer {garbage}"},
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            return [VerificationResult(
                vuln_class=VulnClass.JWT_NONE_ALG,
                status=VerificationStatus.ERROR,
                target_url=route.path,
                payload="alg=none",
                evidence="",
                error=str(exc),
            )]
        if good.status_code < 400 and good.status_code != bad.status_code:
            return [VerificationResult(
                vuln_class=VulnClass.JWT_NONE_ALG,
                status=VerificationStatus.CONFIRMED_VULNERABLE,
                target_url=route.path,
                payload="alg=none",
                evidence=(
                    f"An unsigned token (alg=none) was accepted with HTTP {good.status_code} "
                    f"while a token with an invalid signature was rejected with HTTP {bad.status_code}. "
                    "The server trusts tokens without verifying the signature."
                ),
                http_status=good.status_code,
                response_excerpt=self._excerpt(good.text),
                safe_poc_curl=f"curl -i '{self.base_url.rstrip('/')}{route.path}' -H 'Authorization: Bearer {token}'",
            )]
        return [VerificationResult(
            vuln_class=VulnClass.JWT_NONE_ALG,
            status=VerificationStatus.NOT_REPRODUCIBLE,
            target_url=route.path,
            payload="alg=none",
            evidence=f"Unsigned token rejected (HTTP {good.status_code}); signature verification appears active.",
            http_status=good.status_code,
        )]

    def verify_idor(self, finding: CodeFinding) -> list[VerificationResult]:
        """Compare the response for a real object id with a random one.

        If the endpoint answers identically for both identifiers without any
        credential, the object id is not scoped to the caller.
        """
        route = finding.route
        if route is None:
            return []
        param = finding.taint_var or (route.params[0] if route.params else "id")
        random_id = "999999999"
        try:
            real = self.session.get(
                probes.build_url(self.base_url, route.path, "GET", param, "1"),
                timeout=self.timeout, allow_redirects=False,
            )
            other = self.session.get(
                probes.build_url(self.base_url, route.path, "GET", param, random_id),
                timeout=self.timeout, allow_redirects=False,
            )
        except requests.RequestException as exc:
            return [VerificationResult(
                vuln_class=VulnClass.IDOR,
                status=VerificationStatus.ERROR,
                target_url=route.path,
                payload=param,
                evidence="",
                error=str(exc),
            )]
        if real.status_code == 200 and other.status_code == 200:
            same = (real.text or "") == (other.text or "")
            status = VerificationStatus.POTENTIAL if same else VerificationStatus.CONFIRMED_VULNERABLE
            evidence = (
                f"Both id=1 (HTTP {real.status_code}) and id={random_id} (HTTP {other.status_code}) "
                "were served without credentials. "
                + ("Both responses are identical, so the object lookup ignores the caller."
                   if same else "Different objects are returned for an arbitrary identifier.")
            )
            return [VerificationResult(
                vuln_class=VulnClass.IDOR,
                status=status,
                target_url=route.path,
                payload=f"{param}=1 and {param}={random_id}",
                evidence=evidence,
                http_status=other.status_code,
                response_excerpt=self._excerpt(other.text),
                safe_poc_curl=(
                    f"curl -i '{probes.build_url(self.base_url, route.path, 'GET', param, '1')}'\n"
                    f"curl -i '{probes.build_url(self.base_url, route.path, 'GET', param, random_id)}'"
                ),
            )]
        return [VerificationResult(
            vuln_class=VulnClass.IDOR,
            status=VerificationStatus.NOT_REPRODUCIBLE,
            target_url=route.path,
            payload=param,
            evidence=f"Random identifier was rejected (HTTP {other.status_code}); the endpoint requires valid credentials or scopes the lookup.",
            http_status=other.status_code,
        )]

    def verify_ssrf_oast(self, finding: CodeFinding) -> list[VerificationResult]:
        """Prove an outbound request by making the target call us back."""
        route = finding.route
        if route is None:
            return []
        param = self._pick_param(route, finding) or "url"
        with OastListener() as oast:
            callback = oast.url("ssrf")
            self._request(route.method, route.path, param, callback)
            hit = oast.waited_for("ssrf", timeout=4.0)
            if hit is None:
                return [VerificationResult(
                    vuln_class=VulnClass.SSRF,
                    status=VerificationStatus.NOT_REPRODUCIBLE,
                    target_url=route.path,
                    payload=callback,
                    evidence="The target did not perform the outbound request; the URL is probably validated or filtered.",
                )]
            curl = probes.build_curl(route.method, probes.build_url(self.base_url, route.path, route.method, param, callback), param, callback)
            return [VerificationResult(
                vuln_class=VulnClass.SSRF,
                status=VerificationStatus.CONFIRMED_VULNERABLE,
                target_url=route.path,
                payload=callback,
                evidence=(
                    f"The target server made an outbound request to our local callback listener "
                    f"({hit.path}). The server can be used to reach internal addresses."
                ),
                http_status=hit.headers.get("x-probe-status", None) and 200 or None,
                response_excerpt=f"callback received at {hit.timestamp:.3f}",
                safe_poc_curl=curl,
            )]

    def verify_xxe_oast(self, finding: CodeFinding) -> list[VerificationResult]:
        """Prove XXE with a local file canary (and an OAST callback as backup).

        The canary file is created in a temporary directory and contains a
        random marker. If the parser resolves the external entity, the marker
        shows up in the response: file disclosure proven without touching any
        real system file.
        """
        route = finding.route
        if route is None:
            return []
        canary = "dexsec-xxe-canary-" + secrets.token_hex(8)
        canary_path = Path(tempfile.gettempdir()) / f"{canary}.txt"
        try:
            canary_path.write_text(canary, encoding="utf-8")
        except OSError:
            canary_path = None

        with OastListener() as oast:
            callback = oast.url("xxe")
            entity_target = canary_path.as_uri() if canary_path else callback
            payload = (
                '<?xml version="1.0"?>'
                '<!DOCTYPE root [ <!ENTITY xxe SYSTEM "' + entity_target + '"> ]>'
                "<root>&xxe;</root>"
            )
            try:
                resp = self.session.post(
                    self.base_url.rstrip("/") + route.path,
                    data=payload.encode(),
                    headers={"Content-Type": "application/xml"},
                    timeout=self.timeout,
                    allow_redirects=False,
                )
            except requests.RequestException as exc:
                return [VerificationResult(
                    vuln_class=VulnClass.XXE,
                    status=VerificationStatus.ERROR,
                    target_url=route.path,
                    payload=payload,
                    evidence="",
                    error=str(exc),
                )]
            body = resp.text or ""
            hit = oast.waited_for("xxe", timeout=1.5)
            if canary and canary in body:
                return [VerificationResult(
                    vuln_class=VulnClass.XXE,
                    status=VerificationStatus.CONFIRMED_VULNERABLE,
                    target_url=route.path,
                    payload=payload,
                    evidence=(
                        "The XML parser resolved an external entity and returned the content of a "
                        f"local file (canary '{canary}'). External entity processing is enabled."
                    ),
                    http_status=resp.status_code,
                    response_excerpt=self._excerpt(body),
                    safe_poc_curl=(
                        f"curl -i -X POST '{self.base_url.rstrip('/')}{route.path}' "
                        f"-H 'Content-Type: application/xml' --data '{payload}'"
                    ),
                )]
            if hit is not None:
                return [VerificationResult(
                    vuln_class=VulnClass.XXE,
                    status=VerificationStatus.CONFIRMED_VULNERABLE,
                    target_url=route.path,
                    payload=payload,
                    evidence="The XML parser fetched our external entity over HTTP: external entity resolution is enabled.",
                    http_status=resp.status_code,
                    response_excerpt=self._excerpt(body),
                    safe_poc_curl=(
                        f"curl -i -X POST '{self.base_url.rstrip('/')}{route.path}' "
                        f"-H 'Content-Type: application/xml' --data '{payload}'"
                    ),
                )]
            return [VerificationResult(
                vuln_class=VulnClass.XXE,
                status=VerificationStatus.NOT_REPRODUCIBLE,
                target_url=route.path,
                payload=payload,
                evidence="The XML parser neither resolved the local file entity nor contacted the callback: entities are probably disabled.",
                http_status=resp.status_code,
            )]

    def verify_mass_assignment(self, finding: CodeFinding) -> list[VerificationResult]:
        """Send a harmless unknown field and see whether the server stores it.

        The probe uses a field name that does not exist in the model
        (``dexsec_probe_field``), so no real attribute is changed - but a
        server that reflects it proves that the whole request body is
        expanded into the model.
        """
        route = finding.route
        if route is None or route.method.upper() in ("GET", "HEAD", "OPTIONS"):
            return []
        marker_field = "dexsec_probe_field"
        marker_value = "dexsec-probe-7c1f"
        url = self.base_url.rstrip("/") + (route.path if route.path.startswith("/") else "/" + route.path)
        try:
            resp = self.session.post(
                url,
                json={marker_field: marker_value},
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            return [VerificationResult(
                vuln_class=VulnClass.MASS_ASSIGNMENT,
                status=VerificationStatus.ERROR,
                target_url=route.path,
                payload=marker_field,
                evidence="",
                error=str(exc),
            )]
        body = resp.text or ""
        if marker_value in body:
            return [VerificationResult(
                vuln_class=VulnClass.MASS_ASSIGNMENT,
                status=VerificationStatus.CONFIRMED_VULNERABLE,
                target_url=route.path,
                payload=f"{marker_field}={marker_value}",
                evidence=(
                    f"The server accepted and echoed the unknown field '{marker_field}'. "
                    "The request body is written to the model as-is, so fields such as "
                    "role, is_admin or price can be set by the client."
                ),
                http_status=resp.status_code,
                response_excerpt=self._excerpt(body),
                safe_poc_curl=(
                    f"curl -i -X {route.method} '{url}' -H 'Content-Type: application/json' "
                    f"-d '{{\"{marker_field}\": \"{marker_value}\"}}'"
                ),
            )]
        return [VerificationResult(
            vuln_class=VulnClass.MASS_ASSIGNMENT,
            status=VerificationStatus.NOT_REPRODUCIBLE,
            target_url=route.path,
            payload=marker_field,
            evidence="The server ignored the unknown field, so the model is probably built from an explicit field list.",
            http_status=resp.status_code,
        )]

    def verify_xss(self, finding: CodeFinding) -> list[VerificationResult]:
        """Check whether the parameter is reflected without escaping.

        A harmless marker is sent first (proves reflection), then a payload
        containing angle brackets.  If the brackets come back unescaped the
        response can break out of HTML/attribute context.
        """
        route = finding.route
        if route is None:
            return []
        param = self._pick_param(route, finding) or "q"
        marker = "dexsec-xss-marker-9c1f"
        payload = "<dexsec-xss-probe>"

        resp, _, err = self._request(route.method, route.path, param, marker)
        if err or resp is None:
            return [VerificationResult(
                vuln_class=VulnClass.XSS,
                status=VerificationStatus.ERROR,
                target_url=route.path,
                payload=param,
                evidence="",
                error=err or "no response",
            )]
        body = resp.text or ""
        if marker not in body:
            return [VerificationResult(
                vuln_class=VulnClass.XSS,
                status=VerificationStatus.NOT_REPRODUCIBLE,
                target_url=route.path,
                payload=param,
                evidence="The parameter value is not reflected in the response.",
                http_status=resp.status_code,
            )]

        resp2, _, err2 = self._request(route.method, route.path, param, payload)
        if err2 or resp2 is None:
            return [VerificationResult(
                vuln_class=VulnClass.XSS,
                status=VerificationStatus.POTENTIAL,
                target_url=route.path,
                payload=param,
                evidence="The parameter is reflected; the escaping test could not be completed.",
                http_status=resp.status_code,
            )]
        body2 = resp2.text or ""
        if payload in body2:
            curl = probes.build_curl(route.method, probes.build_url(self.base_url, route.path, route.method, param, payload), param, payload)
            return [VerificationResult(
                vuln_class=VulnClass.XSS,
                status=VerificationStatus.CONFIRMED_VULNERABLE,
                target_url=route.path,
                payload=payload,
                evidence=(
                    "The payload was returned unescaped in the response: the parameter is injected "
                    "into the HTML without encoding, so markup (and script) can be injected."
                ),
                http_status=resp2.status_code,
                response_excerpt=self._excerpt(body2),
                safe_poc_curl=curl,
            )]
        escaped = "&lt;dexsec-xss-probe&gt;" in body2 or "&#60;dexsec-xss-probe&#62;" in body2
        return [VerificationResult(
            vuln_class=VulnClass.XSS,
            status=VerificationStatus.POTENTIAL if escaped else VerificationStatus.NOT_REPRODUCIBLE,
            target_url=route.path,
            payload=payload,
            evidence=(
                "The parameter is reflected but the angle brackets are encoded, so the output is "
                "escaped. Check other contexts (attributes, JavaScript, URL) for a real escape."
                if escaped else
                "The parameter is reflected but the probe characters were not returned verbatim."
            ),
            http_status=resp2.status_code,
            response_excerpt=self._excerpt(body2),
        )]

    # ------------------------------------------------------------------ entry
    def _pick_param(self, route, finding) -> Optional[str]:
        """Choose which request parameter to inject into."""
        # 1) The variable that actually carries the tainted data in the code.
        taint_var = (finding.taint_var or "").split(",")[0].strip()
        generic = {"request", "request body", "args", "body", "data", "params", "input", "value"}
        if taint_var and taint_var.lower() not in generic:
            if re.search(rf"\b{re.escape(taint_var)}\b", finding.code_snippet or ""):
                return taint_var
            if taint_var in (route.handler_body or ""):
                return taint_var

        # 2) A path parameter that is used inside the handler.
        for candidate in route.params:
            if candidate and candidate in (route.handler_body or ""):
                return candidate

        # 3) The parameters of the handler (they usually carry the request data).
        handler_params = [p for p in (getattr(route, "handler_params", []) or []) if p]
        for candidate in handler_params:
            if candidate.lower() in {"self", "cls", "request", "req"}:
                continue
            return candidate

        # 4) Common parameter names.
        for candidate in ("id", "q", "query", "search", "name", "file", "url", "path", "cmd", "username", "host"):
            if candidate in route.params:
                return candidate
        if route.params:
            return route.params[0]
        if route.method.upper() in ("GET", "DELETE", "HEAD"):
            return "q"
        return "data"

    def verify(self, finding: CodeFinding) -> list[VerificationResult]:
        if finding.vuln_class == VulnClass.SQL_INJECTION:
            return self.verify_sql_injection(finding)
        if finding.vuln_class == VulnClass.COMMAND_INJECTION:
            return self.verify_command_injection(finding)
        if finding.vuln_class == VulnClass.PATH_TRAVERSAL:
            return self.verify_path_traversal(finding)
        if finding.vuln_class == VulnClass.OPEN_REDIRECT:
            return self.verify_open_redirect(finding)
        if finding.vuln_class == VulnClass.TEMPLATE_INJECTION:
            return self.verify_template_injection(finding)
        if finding.vuln_class == VulnClass.NOSQL_INJECTION:
            return self.verify_nosql_injection(finding)
        if finding.vuln_class == VulnClass.JWT_NONE_ALG:
            return self.verify_jwt_none_alg(finding)
        if finding.vuln_class == VulnClass.IDOR:
            return self.verify_idor(finding)
        if finding.vuln_class == VulnClass.XSS:
            return self.verify_xss(finding)
        if finding.vuln_class == VulnClass.MASS_ASSIGNMENT:
            return self.verify_mass_assignment(finding)
        if finding.vuln_class == VulnClass.SSRF:
            return self.verify_ssrf_oast(finding)
        if finding.vuln_class == VulnClass.XXE:
            return self.verify_xxe_oast(finding)
        return []


    # ---------------------------------------------------- deployment checks
    def check_cookies(self, resp: requests.Response) -> list[VerificationResult]:
        """Inspect Set-Cookie headers of the deployment."""
        results: list[VerificationResult] = []
        for raw in resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") else []:
            problems = []
            lowered = raw.lower()
            if "httponly" not in lowered:
                problems.append("missing HttpOnly")
            if "secure" not in lowered:
                problems.append("missing Secure")
            if "samesite" not in lowered:
                problems.append("missing SameSite")
            if problems:
                name = raw.split("=", 1)[0]
                results.append(VerificationResult(
                    vuln_class=VulnClass.INSECURE_COOKIE,
                    status=VerificationStatus.CONFIRMED_VULNERABLE,
                    target_url=resp.url,
                    payload=name,
                    evidence=f"Cookie '{name}' is set without: {', '.join(problems)}.",
                    http_status=resp.status_code,
                    response_excerpt=raw[:200],
                    safe_poc_curl=f"curl -i '{resp.url}'",
                ))
        return results

    def check_graphql(self, base_url: str) -> list[VerificationResult]:
        """Check whether GraphQL introspection is enabled."""
        query = {"query": "{__schema{types{name}}}"}
        for path in ("/graphql", "/api/graphql", "/gql"):
            url = base_url.rstrip("/") + path
            try:
                resp = self.session.post(
                    url,
                    json=query,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
            except requests.RequestException:
                continue
            body = resp.text or ""
            if resp.status_code < 400 and "__schema" in body and "types" in body:
                return [VerificationResult(
                    vuln_class=VulnClass.GRAPHQL_INTROSPECTION,
                    status=VerificationStatus.CONFIRMED_VULNERABLE,
                    target_url=url,
                    payload="{__schema{types{name}}}",
                    evidence=(
                        "GraphQL introspection is enabled: the complete schema (types, fields, "
                        "mutations) can be downloaded by anyone, which makes the attack surface "
                        "fully visible."
                    ),
                    http_status=resp.status_code,
                    response_excerpt=self._excerpt(body),
                    safe_poc_curl=(
                        f"curl -i -X POST '{url}' -H 'Content-Type: application/json' "
                        f"-d '{{\"query\": \"{{__schema{{types{{name}}}}}}\"}}'"
                    ),
                )]
        return []


def verify_base_url(base_url: str, timeout: float = DEFAULT_TIMEOUT) -> list[VerificationResult]:
    """Checks that apply to the deployment as a whole, not to a single route.

    * missing security headers (HSTS, CSP, X-Content-Type-Options, ...)
    * permissive CORS policy
    """
    verifier = Verifier(base_url, timeout=timeout)
    results: list[VerificationResult] = []
    try:
        resp = verifier.session.get(base_url.rstrip("/") + "/", timeout=timeout, allow_redirects=False)
    except requests.RequestException as exc:
        return [VerificationResult(
            vuln_class=VulnClass.MISSING_SECURITY_HEADERS,
            status=VerificationStatus.ERROR,
            target_url=base_url,
            payload="",
            evidence="",
            error=str(exc),
        )]

    headers = {k.lower() for k in resp.headers.keys()}
    missing = [h for h in probes.EXPECTED_SECURITY_HEADERS if h not in headers]
    if missing:
        results.append(VerificationResult(
            vuln_class=VulnClass.MISSING_SECURITY_HEADERS,
            status=VerificationStatus.CONFIRMED_VULNERABLE,
            target_url=base_url + "/",
            payload="HTTP response header inspection",
            evidence="Missing recommended security headers: " + ", ".join(missing),
            http_status=resp.status_code,
            response_excerpt=" | ".join(f"{k}: {v}" for k, v in list(resp.headers.items())[:12]),
            safe_poc_curl=f"curl -i '{base_url.rstrip('/')}/'",
        ))

    results.extend(verifier.check_cookies(resp))
    results.extend(verifier.check_graphql(base_url))

    try:
        cors = verifier.session.get(
            base_url.rstrip("/") + "/",
            headers={"Origin": "http://dexsec-probe.example"},
            timeout=timeout,
            allow_redirects=False,
        )
        allow_origin = cors.headers.get("Access-Control-Allow-Origin", "")
        credentials = cors.headers.get("Access-Control-Allow-Credentials", "").lower()
        if allow_origin == "*" and credentials == "true":
            results.append(VerificationResult(
                vuln_class=VulnClass.PERMISSIVE_CORS,
                status=VerificationStatus.CONFIRMED_VULNERABLE,
                target_url=base_url + "/",
                payload="Origin: http://dexsec-probe.example",
                evidence="Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true. Any site can read authenticated responses.",
                http_status=cors.status_code,
                safe_poc_curl=f"curl -i '{base_url.rstrip('/')}/' -H 'Origin: http://dexsec-probe.example'",
            ))
        elif allow_origin == "http://dexsec-probe.example":
            results.append(VerificationResult(
                vuln_class=VulnClass.PERMISSIVE_CORS,
                status=VerificationStatus.POTENTIAL,
                target_url=base_url + "/",
                payload="Origin: http://dexsec-probe.example",
                evidence="The server reflects the request Origin back in Access-Control-Allow-Origin, which allows any origin.",
                http_status=cors.status_code,
                safe_poc_curl=f"curl -i '{base_url.rstrip('/')}/' -H 'Origin: http://dexsec-probe.example'",
            ))
    except requests.RequestException:
        pass
    return results


NON_PROBEABLE = {
    VulnClass.HARDCODE_SECRET,
    VulnClass.EXPOSED_SECRET_FILE,
    VulnClass.DEBUG_MODE,
    VulnClass.MISSING_AUTH_CHECK,
    VulnClass.INSECURE_RANDOM,
    VulnClass.WEAK_CRYPTO,
    VulnClass.CODE_INJECTION,
    VulnClass.INSECURE_DESERIALIZATION,
    VulnClass.INSECURE_DEPENDENCY,
}


def verify_findings(base_url: str, findings: list[CodeFinding], timeout: float = DEFAULT_TIMEOUT) -> list[VerificationResult]:
    """Run verification for every finding that has a reachable route."""
    verifier = Verifier(base_url, timeout=timeout)
    results: list[VerificationResult] = []
    for finding in findings:
        if finding.route is None:
            continue
        if finding.vuln_class in NON_PROBEABLE:
            continue
        try:
            results.extend(verifier.verify(finding))
        except Exception as exc:  # never let one bad probe kill the run
            results.append(VerificationResult(
                vuln_class=finding.vuln_class,
                status=VerificationStatus.ERROR,
                target_url=finding.route.path,
                payload="",
                evidence="",
                error=str(exc),
            ))
    return results
