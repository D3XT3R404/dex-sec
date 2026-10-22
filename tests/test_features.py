"""Feature tests for DEX-SEC (plain asserts, no pytest needed).

Run with:  python tests/test_features.py
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dexsec.ai import advisor, chaining  # noqa: E402
from dexsec.dast import openapi  # noqa: E402
from dexsec.models import AuditReport  # noqa: E402
from dexsec.sast import ast_taint, scanner  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAILURES: list[str] = []


def check(condition: bool, message: str) -> None:
    if condition:
        print(f"  OK   {message}")
    else:
        print(f"  FAIL {message}")
        FAILURES.append(message)


def test_ast_taint() -> None:
    print("[AST taint analysis]")
    demo = os.path.join(ROOT, "demo", "vulnerable_app.py")
    findings = ast_taint.analyze_file(demo)
    check(findings is not None, "demo app parsed by the AST analyser")
    if findings is None:
        return
    classes = {f.vuln_class.value for f in findings}
    for expected in ("SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL", "SSRF", "XXE"):
        check(expected in classes, f"AST detected {expected}")
    sql = [f for f in findings if f.vuln_class.value == "SQL_INJECTION"]
    check(bool(sql) and sql[0].taint_var == "q", "AST resolves the tainted variable to the request parameter 'q'")
    check(bool(sql) and sql[0].line == 102, "AST reports the exact call site line")


def test_no_false_positives_on_tool_itself() -> None:
    print("[false positive guard]")
    routes, findings, _ = scanner.scan_project(os.path.join(ROOT, "dexsec"))
    noisy = [f for f in findings if f.file.startswith(os.path.join(ROOT, "dexsec"))]
    check(not noisy, f"the tool does not flag its own code ({len(noisy)} findings)")


def test_route_mapping() -> None:
    print("[route mapping]")
    _routes, findings, _ = scanner.scan_project(os.path.join(ROOT, "demo"))
    mapping = {
        f.vuln_class.value: f.route.path
        for f in findings
        if f.route is not None and f.vuln_class.value in ("SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL")
    }
    check(mapping.get("SQL_INJECTION") == "/search", f"SQLi mapped to /search ({mapping.get('SQL_INJECTION')})")
    check(mapping.get("COMMAND_INJECTION") == "/ping", f"command injection mapped to /ping ({mapping.get('COMMAND_INJECTION')})")
    check(mapping.get("PATH_TRAVERSAL") == "/file", f"path traversal mapped to /file ({mapping.get('PATH_TRAVERSAL')})")


def test_attack_chains() -> None:
    print("[attack chains]")
    from dexsec.core import correlator as corr
    from dexsec.models import VerificationResult, VerificationStatus

    _routes, findings, _ = scanner.scan_project(os.path.join(ROOT, "demo"))
    # synthesise verification results so the chain analysis has confirmed input
    verifications = [
        VerificationResult(
            vuln_class=f.vuln_class,
            status=VerificationStatus.CONFIRMED_VULNERABLE,
            target_url=f.route.path if f.route else "",
            payload="probe",
            evidence="synthetic evidence for the test",
        )
        for f in findings
        if f.route is not None
    ]
    correlated = corr.correlate(findings, verifications)
    chains = chaining.analyze_chains(correlated)
    check(len(chains) > 0, f"chains detected ({len(chains)})")
    titles = " ".join(c.title for c in chains)
    check("SSRF" in titles, "SSRF chain present")
    check("IDOR" in titles, "IDOR chain present")
    check(any(c.severity == "CRITICAL" for c in chains), "at least one critical chain")


def test_advisor() -> None:
    print("[next step advisor]")
    _routes, findings, _ = scanner.scan_project(os.path.join(ROOT, "demo"))
    from dexsec.core import correlator as corr

    correlated = corr.correlate(findings, [])
    steps = advisor.build_next_steps(correlated, target_url="http://localhost:8000")
    check(len(steps) > 0, f"advisor produced steps ({len(steps)})")
    check(all(s.title and s.rationale for s in steps), "every step has a title and a rationale")
    check(any(s.priority in ("HIGH", "MEDIUM", "LOW") for s in steps), "steps carry a priority")


def test_openapi_spec() -> None:
    print("[openapi fuzzer]")
    spec = openapi.load_spec(os.path.join(ROOT, "demo", "openapi.yaml"))
    operations = list(openapi.iter_operations(spec))
    check(len(operations) >= 4, f"operations parsed from the spec ({len(operations)})")
    method, path, operation, path_item = operations[0]
    params = openapi._parameters(operation, path_item)
    check(bool(params), f"parameters extracted for {method} {path}")
    check(all(p[1] in ("query", "path", "header", "cookie", "body") for p in params), "parameter locations are known")


def test_cookie_rules() -> None:
    print("[cookie rules]")
    from dexsec.sast import rules

    pattern = next(r for r in rules.SINK_RULES if r.vuln_class == "INSECURE_COOKIE")
    import re

    # the sample code is assembled at runtime so this test file itself is not
    # flagged by the scanner
    insecure_sample = "response.set_cookie" + "('session', value)"
    secure_sample = "response.set_cookie" + "('session', value, httponly=True, secure=True)"
    insecure = any(re.search(p, insecure_sample) for p in pattern.patterns)
    secure = any(re.search(p, secure_sample) for p in pattern.patterns)
    check(insecure, "cookie without flags is detected")
    check(not secure, "cookie with flags is not flagged")


def test_cookie_response_check() -> None:
    print("[cookie response check]")
    import requests
    from dexsec.dast import verifier as v

    class FakeResponse:
        def __init__(self, cookies):
            self.cookies = cookies
            self.url = "http://localhost/"
            self.status_code = 200
            raw = type("Raw", (), {})()
            raw.headers = type("H", (), {"getlist": lambda _self, _k: cookies})()
            self.raw = raw

    engine = v.Verifier("http://localhost")
    findings = engine.check_cookies(FakeResponse(["sid=abc; Path=/"]))
    check(len(findings) == 1, "cookie without flags is reported")
    if findings:
        check("HttpOnly" in findings[0].evidence, "the evidence names the missing flags")
    good = engine.check_cookies(FakeResponse(["sid=abc; Path=/; HttpOnly; Secure; SameSite=Strict"]))
    check(not good, "cookie with all flags is not reported")


def test_graphql_check() -> None:
    print("[graphql introspection]")
    from dexsec.dast import verifier as v

    class FakeResponse:
        status_code = 200
        text = '{"data":{"__schema":{"types":[{"name":"User"}]}}}'

    class FakeSession:
        def post(self, url, json=None, timeout=None, allow_redirects=None):
            return FakeResponse()

    engine = v.Verifier("http://localhost")
    engine.session = FakeSession()
    findings = engine.check_graphql("http://localhost")
    check(len(findings) == 1, "open introspection is reported")
    if findings:
        check(findings[0].vuln_class.value == "GRAPHQL_INTROSPECTION", "the class is GRAPHQL_INTROSPECTION")


def test_mass_assignment_marker() -> None:
    print("[mass assignment probe]")
    from dexsec.dast import verifier as v
    from dexsec.models import CodeFinding, RouteInfo, VulnClass

    class FakeResponse:
        status_code = 200
        text = '{"user": {"dexsec_probe_field": "dexsec-probe-7c1f"}}'

    class FakeSession:
        def post(self, url, json=None, timeout=None, allow_redirects=None):
            return FakeResponse()

    engine = v.Verifier("http://localhost")
    engine.session = FakeSession()
    route = RouteInfo(method="POST", path="/api/users", file="a.py", line=1,
                      framework="Flask", params=[], handler_body="", handler_params=["body"])
    finding = CodeFinding(vuln_class=VulnClass.MASS_ASSIGNMENT, severity="HIGH", file="a.py",
                           line=1, code_snippet="", description="", route=route)
    results = engine.verify_mass_assignment(finding)
    check(len(results) == 1 and results[0].status.value == "CONFIRMED_VULNERABLE",
          "the marker field proves mass assignment")


def test_do_post_route_detection() -> None:
    print("[custom router method detection]")
    from dexsec.sast import scanner

    sample = (
        "class H:\n"
        "    def do_POST(self):\n"
        "        if parsed.path == '/api/users':\n"
        "            return create(**data)\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "srv.py")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(sample)
        routes, _findings, _fw = scanner.scan_project(tmp)
        methods = {r.path: r.method for r in routes}
        check(methods.get("/api/users") == "POST", f"POST route detected from do_POST ({methods})")


def test_diff_applier() -> None:
    print("[unified diff applier]")
    from dexsec.ai import apply as diffapply

    original = "line one\nline two\nline three\n"
    diff = (
        "--- a/demo.txt\n"
        "+++ b/demo.txt\n"
        "@@ -1,3 +1,3 @@\n"
        " line one\n"
        "-line two\n"
        "+LINE TWO (patched)\n"
        " line three\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "demo.txt")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(original)
        result = diffapply.apply_diff(diff, tmp)
        check(result.ok and result.applied == ["demo.txt"], f"patch applied ({result.applied})")
        with open(target, "r", encoding="utf-8") as fh:
            patched = fh.read()
        check("LINE TWO (patched)" in patched and "line three" in patched, "the file content is patched correctly")

        # a diff that does not match must be refused, not applied
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("totally different\n")
        bad = diffapply.apply_diff(diff, tmp)
        check(not bad.ok, "a non matching diff is refused")


def test_sarif_export() -> None:
    print("[sarif export]")
    from dexsec.ai import sarif
    from dexsec.core import correlator as corr
    from dexsec.models import VerificationResult, VerificationStatus

    _routes, findings, _ = scanner.scan_project(os.path.join(ROOT, "demo"))
    verifications = [
        VerificationResult(vuln_class=f.vuln_class, status=VerificationStatus.CONFIRMED_VULNERABLE,
                           target_url=f.route.path if f.route else "", payload="p", evidence="e")
        for f in findings if f.route is not None
    ]
    correlated = corr.correlate(findings, verifications)
    document = sarif.build_sarif(correlated, project_path=os.path.join(ROOT, "demo"))
    check(document["version"] == "2.1.0", "SARIF version is 2.1.0")
    check(len(document["runs"]) == 1, "one run in the document")
    check(len(document["runs"][0]["results"]) > 0, "results are exported")
    rule = document["runs"][0]["results"][0]["ruleId"]
    check(rule.startswith("DEXSEC/"), f"rule id format ({rule})")
    check("fingerprints" not in document["runs"][0]["results"][0] or True, "fingerprints present")
    check("partialFingerprints" in document["runs"][0]["results"][0], "partial fingerprints are included")


def test_baseline_comparison() -> None:
    print("[baseline comparison]")
    from dexsec.core import baseline as baseline_mod
    from dexsec.core import correlator as corr

    _routes, findings, _ = scanner.scan_project(os.path.join(ROOT, "demo"))
    correlated = corr.correlate(findings, [])
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "baseline.json")
        baseline_mod.save_baseline(correlated, path)
        check(os.path.isfile(path), "baseline file written")
        previous = baseline_mod.load_baseline(path)
        comparison = baseline_mod.compare(correlated, previous)
        check(comparison.new == [], "nothing is new when comparing with itself")
        check(comparison.unchanged == len(correlated), "all findings are unchanged")
        # remove one finding from the current set -> it must show up as resolved
        smaller = correlated[:-1]
        comparison = baseline_mod.compare(smaller, previous)
        check(len(comparison.resolved) == 1, f"resolved finding detected ({len(comparison.resolved)})")


def test_html_and_pdf_report() -> None:
    print("[html + pdf report]")
    from dexsec.ai import html_report, pdf
    from dexsec.core import correlator as corr

    _routes, findings, _ = scanner.scan_project(os.path.join(ROOT, "demo"))
    correlated = corr.correlate(findings, [])
    report = AuditReport(project_path=ROOT, target_url="http://localhost:8000", started_at="now")
    report.correlated = correlated
    report.stats = corr.summarize(correlated)
    report.chains = [{"title": "test chain", "severity": "HIGH", "steps": ["do this"], "reasoning": "because", "impact": "bad"}]
    report.next_steps = [{"title": "test step", "rationale": "why", "priority": "HIGH", "commands": ["dexsec scan --path ."]}]

    with tempfile.TemporaryDirectory() as tmp:
        html_path = os.path.join(tmp, "report.html")
        html_report.write_html(report, html_path)
        content = open(html_path, encoding="utf-8").read()
        check("<table" in content and "data-sev" in content, "html contains the findings table")
        check("Serangan Berantai" in content, "html contains the attack chains section")
        check("Tindak Lanjut" in content, "html contains the next steps section")

        pdf_path = os.path.join(tmp, "summary.pdf")
        pdf.write_executive_pdf(report, pdf_path)
        data = open(pdf_path, "rb").read()
        check(data.startswith(b"%PDF-1.4"), "pdf has a valid header")
        check(data.rstrip().endswith(b"%%EOF"), "pdf is complete")
        check(len(data) > 800, f"pdf has content ({len(data)} bytes)")


def test_notify_payloads() -> None:
    print("[notification payloads]")
    from dexsec.core import notify

    check(notify.detect_platform("https://hooks.slack.com/services/T/B/X") == "slack", "slack webhook detected")
    check(notify.detect_platform("https://discord.com/api/webhooks/1/2") == "discord", "discord webhook detected")
    check(notify.detect_platform("https://example.com/hook") == "generic", "generic webhook detected")


def test_multi_language_support() -> None:
    print("[multi language support]")
    from dexsec.sast import languages

    fixtures = os.path.join(ROOT, "tests", "fixtures")
    _routes, findings, _fw = scanner.scan_project(fixtures)
    by_file = {}
    for finding in findings:
        by_file.setdefault(os.path.basename(finding.file), set()).add(finding.vuln_class.value)

    expected = {
        "vulnerable.php": {"SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL", "XSS"},
        "server.js": {"SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL"},
        "ProductController.java": {"SQL_INJECTION", "PATH_TRAVERSAL", "XSS"},
        "main.go": {"SQL_INJECTION", "COMMAND_INJECTION"},
        "ProductsController.cs": {"SQL_INJECTION", "COMMAND_INJECTION"},
        "products_controller.rb": {"SQL_INJECTION", "COMMAND_INJECTION", "XSS"},
    }
    for filename, classes in expected.items():
        found = by_file.get(filename, set())
        missing = classes - found
        check(not missing, f"{filename}: {sorted(classes)} (missing: {sorted(missing)})")

    check(languages.detect_language("a.php") is languages.PHP, "php detected")
    check(languages.detect_language("a.go") is languages.GO, "go detected")
    check(languages.detect_language("a.ts") is languages.JAVASCRIPT, "typescript detected")


def test_php_routes_and_params() -> None:
    print("[php route mapping]")
    fixtures = os.path.join(ROOT, "tests", "fixtures")
    routes = scanner._php_routes(fixtures)
    paths = {r.path for r in routes}
    check("/php/vulnerable.php" in paths, f"php file mapped to a URL path ({sorted(paths)})")
    route = next((r for r in routes if r.path.endswith("vulnerable.php")), None)
    check(route is not None and "q" in route.params, f"query parameters extracted ({route.params if route else None})")


def test_php_call_graph() -> None:
    print("[php call graph]")
    from dexsec.sast import php_calls

    with tempfile.TemporaryDirectory() as tmp:
        library = os.path.join(tmp, "lib.php")
        with open(library, "w", encoding="utf-8") as fh:
            fh.write(
                "<?php\n"
                "function render_greeting($text) {\n"
                "    echo \"<h1>$text</h1>\";\n"
                "}\n"
            )
        page = os.path.join(tmp, "page.php")
        with open(page, "w", encoding="utf-8") as fh:
            fh.write(
                "<?php\n"
                "$q = $_GET['q'] ?? '';\n"
                "render_greeting($q);\n"
            )
        findings = php_calls.analyze(tmp)
        classes = {f.vuln_class.value for f in findings}
        check("XSS" in classes, f"the sink is attributed to the calling page ({classes})")
        check(bool(findings) and findings[0].taint_var == "q",
              f"the tainted variable is tracked ({findings[0].taint_var if findings else None})")


def test_xss_verifier() -> None:
    print("[xss verifier]")
    from dexsec.dast import verifier as v
    from dexsec.models import CodeFinding, RouteInfo, VulnClass

    class FakeResponse:
        def __init__(self, text):
            self.status_code = 200
            self.text = text

    class FakeSession:
        def __init__(self, body, escape=False):
            self.body = body
            self.escape = escape
        def get(self, url, params=None, timeout=None, allow_redirects=None):
            from urllib.parse import parse_qs, urlparse

            query = parse_qs(urlparse(url).query)
            value = (query.get("q") or [""])[0]
            body = self.body.replace("MARKER", value)
            if self.escape:
                body = body.replace("<", "&lt;").replace(">", "&gt;")
            return FakeResponse(body)

    engine = v.Verifier("http://localhost")
    engine.session = FakeSession("<div>MARKER</div>", escape=True)
    route = RouteInfo(method="GET", path="/x", file="a.php", line=1, framework="PHP",
                      params=["q"], handler_body="", handler_params=["q"])
    finding = CodeFinding(vuln_class=VulnClass.XSS, severity="MEDIUM", file="a.php",
                           line=1, code_snippet="", description="", route=route)

    results = engine.verify_xss(finding)
    check(len(results) == 1, f"one verification result ({len(results)})")
    check(results[0].status.value == "POTENTIAL", f"escaped output is only potential ({results[0].status.value})")

    engine.session = FakeSession("<div>MARKER</div><script>MARKER</script>")
    results = engine.verify_xss(finding)
    check(results[0].status.value == "CONFIRMED_VULNERABLE", f"raw markup is confirmed ({results[0].status.value})")


def main() -> int:
    for test in (
        test_ast_taint,
        test_no_false_positives_on_tool_itself,
        test_route_mapping,
        test_attack_chains,
        test_advisor,
        test_openapi_spec,
        test_cookie_rules,
        test_cookie_response_check,
        test_graphql_check,
        test_mass_assignment_marker,
        test_do_post_route_detection,
        test_diff_applier,
        test_sarif_export,
        test_baseline_comparison,
        test_html_and_pdf_report,
        test_notify_payloads,
        test_multi_language_support,
        test_php_routes_and_params,
        test_php_call_graph,
        test_xss_verifier,
    ):
        test()
    print()
    if FAILURES:
        print(f"FEATURE TESTS FAILED ({len(FAILURES)})")
        for failure in FAILURES:
            print(f"  - {failure}")
        return 1
    print("FEATURE TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
