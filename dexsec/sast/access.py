"""Access control analysis: IDOR / BOLA and missing authorisation checks.

Heuristic approach
------------------
A route that accepts a directly addressable object identifier is an IDOR
candidate.  When the handler contains no marker of an ownership or role check
the candidate is reported.  The check is intentionally conservative: it never
claims certainty, the external verification phase decides how severe it is.
"""

from __future__ import annotations

import re

from ..models import CodeFinding, RouteInfo, Severity, VulnClass
from . import rules

# Patterns that show the handler scopes the query to the current user.
OWNERSHIP_MARKERS = [
    r"current_user", r"request\.user", r"req\.user", r"session\[", r"ctx\.state\.user",
    r"g\.user", r"auth\.current", r"get_current_user", r"user\.id\s*==", r"\.user_id\s*==",
    r"owner", r"created_by", r"user_id\s*==\s*", r"account_id\s*==",
]

ROLE_MARKERS = [
    r"is_admin", r"is_staff", r"is_superuser", r"role\s*==", r"has_permission",
    r"permission_required", r"require_role", r"authorize", r"can_edit", r"policy",
    r"@permission_required", r"@requires_auth", r"@login_required", r"@jwt_required",
    r"@auth", r"login_required", r"verify_token", r"verify_jwt", r"current_user",
    r"request\.user", r"req\.user", r"authenticate", r"api_key", r"Authorization",
    r"jwt\.decode", r"access_token", r"session\[",
]

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _handler_code(route: RouteInfo) -> str:
    return (route.handler_body or "") + "\n" + (route.source_excerpt or "")


def _has_marker(handler: str, markers: list[str]) -> bool:
    return any(re.search(marker, handler, re.IGNORECASE) for marker in markers)


def _id_params(route: RouteInfo) -> list[str]:
    candidates = list(route.params) + list(getattr(route, "handler_params", []) or [])
    return [p for p in dict.fromkeys(candidates) if p.lower() in rules.ID_PARAM_NAMES]


CSRF_MARKERS = [
    r"csrf", r"xsrf", r"csrf_token", r"csrfToken", r"X-CSRF", r"authenticity_token",
    r"same_site", r"@csrf\.exempt",
]


def analyze_access_control(routes: list[RouteInfo]) -> list[CodeFinding]:
    """Report IDOR candidates and handlers without any authorisation check."""
    findings: list[CodeFinding] = []

    for route in routes:
        handler = _handler_code(route)
        id_params = _id_params(route)

        if id_params:
            has_ownership = _has_marker(handler, OWNERSHIP_MARKERS)
            has_role = _has_marker(handler, ROLE_MARKERS)
            if not has_ownership and not has_role:
                findings.append(
                    CodeFinding(
                        vuln_class=VulnClass.IDOR,
                        severity=Severity.HIGH,
                        file=route.file,
                        line=route.line,
                        code_snippet=route.source_excerpt or handler[:300],
                        description=(
                            f"Route exposes a directly addressable object ({', '.join(id_params)}) "
                            "without any ownership or role check in the handler: "
                            "classic IDOR / BOLA candidate."
                        ),
                        cwe="CWE-639",
                        route=route,
                        taint_var=id_params[0],
                        sink=route.path,
                        confidence=0.55,
                    )
                )
            elif not has_ownership and has_role:
                findings.append(
                    CodeFinding(
                        vuln_class=VulnClass.IDOR,
                        severity=Severity.MEDIUM,
                        file=route.file,
                        line=route.line,
                        code_snippet=route.source_excerpt or handler[:300],
                        description=(
                            f"Route exposes {', '.join(id_params)} and only performs a role check, "
                            "without verifying that the object belongs to the caller."
                        ),
                        cwe="CWE-639",
                        route=route,
                        taint_var=id_params[0],
                        sink=route.path,
                        confidence=0.4,
                    )
                )

        # A mutating route without any authentication marker is worth a look.
        if route.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            has_role = _has_marker(handler, ROLE_MARKERS)
            if not has_role:
                findings.append(
                    CodeFinding(
                        vuln_class=VulnClass.MISSING_AUTH_CHECK,
                        severity=Severity.MEDIUM,
                        file=route.file,
                        line=route.line,
                        code_snippet=route.source_excerpt or handler[:300],
                        description=(
                            f"State changing route {route.method} {route.path} shows no "
                            "authentication or authorisation check in the handler."
                        ),
                        cwe="CWE-306",
                        route=route,
                        sink=route.path,
                        confidence=0.4,
                    )
                )

        # State changing route without any CSRF protection.
        if route.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            has_csrf = _has_marker(handler, CSRF_MARKERS)
            has_role = _has_marker(handler, ROLE_MARKERS)
            if not has_csrf and has_role:
                findings.append(
                    CodeFinding(
                        vuln_class=VulnClass.CSRF_MISSING,
                        severity=Severity.MEDIUM,
                        file=route.file,
                        line=route.line,
                        code_snippet=route.source_excerpt or handler[:300],
                        description=(
                            f"State changing route {route.method} {route.path} authenticates the user "
                            "but shows no CSRF token validation."
                        ),
                        cwe="CWE-352",
                        route=route,
                        sink=route.path,
                        confidence=0.35,
                    )
                )
    return findings
