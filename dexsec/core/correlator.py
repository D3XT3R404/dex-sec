"""Correlates internal code findings with external verification results.

This is the heart of the "inside-out" idea: a finding only reaches CRITICAL
when the code really contains a sink AND the live target actually proved it.
"""

from __future__ import annotations

from ..models import (
    CodeFinding,
    CorrelatedFinding,
    Severity,
    VerificationResult,
    VerificationStatus,
    VulnClass,
)

IMPACT_TEXT = {
    VulnClass.SQL_INJECTION: "Attacker-controlled input reaches a SQL statement, allowing reading, modifying or deleting arbitrary database records and potentially leading to full server compromise via chained techniques.",
    VulnClass.NOSQL_INJECTION: "Attacker-controlled operators reach a NoSQL query, allowing bypass of intended filters, mass data extraction or authentication bypass.",
    VulnClass.COMMAND_INJECTION: "Attacker-controlled input reaches an OS command execution API, allowing arbitrary command execution on the host with the privileges of the application process.",
    VulnClass.CODE_INJECTION: "Attacker-controlled input reaches a dynamic evaluation API, allowing arbitrary code execution inside the application process.",
    VulnClass.TEMPLATE_INJECTION: "User input is rendered by the server-side template engine, which allows reading files, executing code and full server compromise.",
    VulnClass.INSECURE_DESERIALIZATION: "Untrusted data is deserialised with a native deserialiser, which frequently leads to remote code execution.",
    VulnClass.XXE: "XML is parsed with external entity resolution enabled, allowing local file disclosure, SSRF and denial of service.",
    VulnClass.PATH_TRAVERSAL: "Attacker-controlled input reaches a file path operation, allowing reading or writing files outside the intended directory.",
    VulnClass.EXPOSED_SECRET_FILE: "Credential material is committed with the source code, exposing it to everybody with repository access and to every CI system that clones it.",
    VulnClass.SSRF: "Attacker-controlled URL reaches an outbound HTTP client, allowing the server to be used as a proxy into internal networks and cloud metadata services.",
    VulnClass.OPEN_REDIRECT: "The redirect target is fully controlled by the request, enabling phishing and OAuth token theft through a trusted domain.",
    VulnClass.IDOR: "An object identifier is accepted without verifying that the object belongs to the caller, letting one user read or modify another user's data.",
    VulnClass.MISSING_AUTH_CHECK: "A state changing endpoint shows no authentication or authorisation check, so it may be callable by anyone.",
    VulnClass.MASS_ASSIGNMENT: "Request data is expanded directly into a model, so the client can set privileged fields such as role, is_admin or balance.",
    VulnClass.CSRF_MISSING: "A cookie authenticated state changing endpoint has no CSRF token check, so another website can trigger the action in the user's browser.",
    VulnClass.WEAK_CRYPTO: "Weak hash or cipher usage allows password cracking, collision attacks or downgrade of the protection strength.",
    VulnClass.INSECURE_RANDOM: "Predictable randomness is used for security relevant values, allowing tokens, sessions or nonces to be guessed.",
    VulnClass.JWT_NONE_ALG: "The server accepts tokens without verifying the signature, so anyone can forge any identity and role.",
    VulnClass.DEBUG_MODE: "Debug mode exposes stack traces, environment variables and sometimes an interactive console, which massively eases exploitation.",
    VulnClass.INSECURE_COOKIE: "A session cookie without HttpOnly/Secure/SameSite can be stolen through XSS, read by a network attacker, or sent along with cross site requests.",
    VulnClass.SESSION_FIXATION: "The session identifier can be chosen by the client, so an attacker can force a victim to use a known session.",
    VulnClass.PERMISSIVE_CORS: "Any website can read authenticated responses of the API, which effectively removes the browser based origin protection.",
    VulnClass.MISSING_SECURITY_HEADERS: "Missing browser security headers weaken the defence in depth against XSS, clickjacking and protocol downgrade attacks.",
    VulnClass.INSECURE_DEPENDENCY: "A dependency or build step is known to be unsafe.",
    VulnClass.GRAPHQL_INTROSPECTION: "GraphQL introspection exposes the complete schema, so an attacker knows every type, field and mutation before sending a single request.",
    VulnClass.HARDCODE_SECRET: "A credential appears to be embedded directly in the source code, exposing it to anyone with repository access.",
    VulnClass.XSS: "User input is reflected into an HTML response without escaping, enabling script execution in the victim's browser.",
    VulnClass.UNKNOWN: "Potential security issue detected.",
}

REMEDIATION_TEXT = {
    VulnClass.SQL_INJECTION: "Use parameterised queries / prepared statements. Never build SQL by concatenating or formatting user input.",
    VulnClass.NOSQL_INJECTION: "Cast request values to the expected type before querying and reject objects containing operators such as $ne, $gt or $regex.",
    VulnClass.COMMAND_INJECTION: "Avoid passing user input to a shell. Use a fixed argument list with shell=False and validate the value against a strict allow-list.",
    VulnClass.CODE_INJECTION: "Never evaluate user input. Use a parser or an explicit dispatch table instead of eval/exec.",
    VulnClass.TEMPLATE_INJECTION: "Render fixed templates only. Never pass user input into a template engine, and sandbox the template environment.",
    VulnClass.INSECURE_DESERIALIZATION: "Use a data-only format such as JSON, or sign the payload and verify the signature before deserialising it.",
    VulnClass.XXE: "Disable external entity resolution (defusedxml, or lxml with resolve_entities=False and no_network=True).",
    VulnClass.PATH_TRAVERSAL: "Resolve the path, verify it stays inside the intended base directory (os.path.commonpath / Path.resolve + is_relative_to), and reject paths containing '..'.",
    VulnClass.EXPOSED_SECRET_FILE: "Remove the file from the repository, rotate the exposed credential and store it in a secret manager or environment variable.",
    VulnClass.SSRF: "Validate the URL against an allow-list of permitted hosts/schemes, block private and link-local ranges, and disable redirect following.",
    VulnClass.OPEN_REDIRECT: "Accept only relative redirect targets, or compare the target against an allow-list of known destinations.",
    VulnClass.IDOR: "Scope every lookup to the authenticated user (query by owner id) and verify the object belongs to the caller before returning or mutating it.",
    VulnClass.MISSING_AUTH_CHECK: "Apply the authentication/authorisation decorator or middleware to the route and deny anonymous access by default.",
    VulnClass.MASS_ASSIGNMENT: "Pick the allowed fields explicitly instead of **request.json, and never let the client set role, is_admin, price or balance fields.",
    VulnClass.CSRF_MISSING: "Enable CSRF protection (Flask-WTF, Django middleware, csurf, SameSite=Strict cookies) or require a custom header token for state changing requests.",
    VulnClass.WEAK_CRYPTO: "Use SHA-256 or better (argon2/bcrypt/scrypt for passwords) and never disable TLS certificate verification.",
    VulnClass.INSECURE_RANDOM: "Use the secrets module (secrets.token_urlsafe, secrets.choice) for tokens, session ids and nonces.",
    VulnClass.JWT_NONE_ALG: "Pin the accepted algorithms (for example algorithms=['HS256']), always verify the signature and set a reasonable expiry.",
    VulnClass.DEBUG_MODE: "Disable debug mode in production (DEBUG=False) and return generic error pages instead of stack traces.",
    VulnClass.INSECURE_COOKIE: "Set the cookie with httponly=True, secure=True and samesite='Lax' (or 'Strict').",
    VulnClass.SESSION_FIXATION: "Never accept a client supplied session id. Regenerate the session after login (request.session.regenerate / session.rotate).",
    VulnClass.PERMISSIVE_CORS: "Restrict Access-Control-Allow-Origin to an explicit allow-list of trusted origins and never combine it with allow_credentials=true.",
    VulnClass.MISSING_SECURITY_HEADERS: "Add Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options and Referrer-Policy headers.",
    VulnClass.INSECURE_DEPENDENCY: "Pin the dependency to a fixed, patched version and verify the download checksum.",
    VulnClass.GRAPHQL_INTROSPECTION: "Disable introspection in production (disableIntrospection: true) or restrict it to authenticated administrators.",
    VulnClass.HARDCODE_SECRET: "Move the secret into environment variables or a secret manager, rotate the exposed credential, and add it to .gitignore.",
    VulnClass.XSS: "Escape output for the target context (html.escape / framework auto-escaping) and apply a strict Content-Security-Policy.",
    VulnClass.UNKNOWN: "Review the code path and apply input validation plus context-appropriate output encoding.",
}


def _escalate(base: Severity, delta: int) -> Severity:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    idx = order.index(base) if base in order else 0
    return order[min(idx + delta, len(order) - 1)]


def correlate(findings: list[CodeFinding], verifications: list[VerificationResult]) -> list[CorrelatedFinding]:
    """Merge the two result sets into a single ranked list of issues."""
    by_location: dict[tuple, list[VerificationResult]] = {}
    for result in verifications:
        by_location.setdefault((result.vuln_class, result.target_url), []).append(result)

    correlated: list[CorrelatedFinding] = []

    for finding in findings:
        location = (finding.vuln_class, finding.route.path if finding.route else None)
        candidates = by_location.get(location, [])
        best: VerificationResult | None = None
        for candidate in candidates:
            if best is None:
                best = candidate
                continue
            priority = {
                VerificationStatus.CONFIRMED_VULNERABLE: 3,
                VerificationStatus.POTENTIAL: 2,
                VerificationStatus.ERROR: 1,
                VerificationStatus.NOT_REPRODUCIBLE: 0,
                VerificationStatus.SKIPPED: -1,
            }
            if priority.get(candidate.status, 0) > priority.get(best.status, 0):
                best = candidate

        if best is None:
            status = VerificationStatus.SKIPPED
            severity = finding.severity
        elif best.status == VerificationStatus.CONFIRMED_VULNERABLE:
            status = best.status
            severity = _escalate(finding.severity, 1)
        elif best.status == VerificationStatus.POTENTIAL:
            status = best.status
            severity = finding.severity
        elif best.status == VerificationStatus.ERROR:
            status = best.status
            severity = finding.severity
        else:
            status = VerificationStatus.NOT_REPRODUCIBLE
            severity = Severity.LOW

        title = f"{finding.vuln_class.value} in {finding.file}:{finding.line}"
        if finding.route:
            title += f" ({finding.route.method} {finding.route.path})"

        correlated.append(
            CorrelatedFinding(
                finding=finding,
                verification=best,
                final_severity=severity,
                status=status,
                title=title,
                impact=IMPACT_TEXT.get(finding.vuln_class, IMPACT_TEXT[VulnClass.UNKNOWN]),
                remediation_hint=REMEDIATION_TEXT.get(finding.vuln_class, REMEDIATION_TEXT[VulnClass.UNKNOWN]),
            )
        )

    # Findings with no route at all (e.g. hardcoded secrets) still matter.
    order = {
        VerificationStatus.CONFIRMED_VULNERABLE: 0,
        VerificationStatus.POTENTIAL: 1,
        VerificationStatus.ERROR: 2,
        VerificationStatus.SKIPPED: 3,
        VerificationStatus.NOT_REPRODUCIBLE: 4,
    }
    sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    correlated.sort(key=lambda c: (order.get(c.status, 9), sev_order.get(c.final_severity, 9), -c.finding.confidence))
    return correlated


def standalone_findings(
    verifications: list[VerificationResult],
    findings: list[CodeFinding],
) -> list[CorrelatedFinding]:
    """Turn deployment level results (headers, CORS) into report entries.

    These checks are not tied to a single code location, so they are not
    produced by the normal correlation step.
    """
    already = {f.vuln_class for f in findings}
    result: list[CorrelatedFinding] = []
    for verification in verifications:
        if verification.vuln_class in already:
            continue
        if verification.status not in (VerificationStatus.CONFIRMED_VULNERABLE, VerificationStatus.POTENTIAL):
            continue
        severity = Severity.HIGH if verification.status == VerificationStatus.CONFIRMED_VULNERABLE else Severity.MEDIUM
        synthetic = CodeFinding(
            vuln_class=verification.vuln_class,
            severity=severity,
            file=verification.target_url,
            line=0,
            code_snippet=verification.payload,
            description=verification.evidence,
            cwe="CWE-16",
            sink=verification.payload,
            confidence=0.8,
        )
        result.append(
            CorrelatedFinding(
                finding=synthetic,
                verification=verification,
                final_severity=severity,
                status=verification.status,
                title=f"{verification.vuln_class.value} (deployment level check)",
                impact=IMPACT_TEXT.get(verification.vuln_class, IMPACT_TEXT[VulnClass.UNKNOWN]),
                remediation_hint=REMEDIATION_TEXT.get(verification.vuln_class, REMEDIATION_TEXT[VulnClass.UNKNOWN]),
            )
        )
    return result


def summarize(correlated: list[CorrelatedFinding]) -> dict:
    """Build a statistics block for the report."""
    confirmed = [c for c in correlated if c.status == VerificationStatus.CONFIRMED_VULNERABLE]
    potential = [c for c in correlated if c.status == VerificationStatus.POTENTIAL]
    by_severity: dict[str, int] = {}
    by_class: dict[str, int] = {}
    for item in correlated:
        by_severity[item.final_severity.value] = by_severity.get(item.final_severity.value, 0) + 1
        key = item.finding.vuln_class.value
        by_class[key] = by_class.get(key, 0) + 1
    return {
        "total": len(correlated),
        "confirmed": len(confirmed),
        "potential": len(potential),
        "not_reproducible": len([c for c in correlated if c.status == VerificationStatus.NOT_REPRODUCIBLE]),
        "by_severity": by_severity,
        "by_vuln_class": by_class,
    }
