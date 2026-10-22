"""Attack chain analysis.

Individual findings are rarely the whole story.  This module looks at the
confirmed findings of a run and detects well known chains, for example:

    SSRF  ->  reaches the internal metadata service  ->  cloud credentials
    IDOR  ->  reads another user's data               ->  account takeover
    Open redirect  ->  steals an OAuth token           ->  account takeover
    SSTI / command injection  ->  RCE                   ->  full compromise

Each chain is rated (LOW/MEDIUM/HIGH/CRITICAL) and comes with the reasoning
that links the individual findings together.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..models import CorrelatedFinding, VerificationStatus, VulnClass


@dataclass
class Chain:
    title: str
    severity: str
    steps: list[str] = field(default_factory=list)
    reasoning: str = ""
    impact: str = ""
    involved: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "steps": self.steps,
            "reasoning": self.reasoning,
            "impact": self.impact,
            "involved": self.involved,
            "references": self.references,
        }


def _confirmed(correlated: list[CorrelatedFinding]) -> list[CorrelatedFinding]:
    return [
        item for item in correlated
        if item.status in (VerificationStatus.CONFIRMED_VULNERABLE, VerificationStatus.POTENTIAL)
    ]


def _find(correlated: list[CorrelatedFinding], *classes: VulnClass) -> list[CorrelatedFinding]:
    return [item for item in correlated if item.finding.vuln_class in classes]


def analyze_chains(correlated: list[CorrelatedFinding]) -> list[Chain]:
    """Detect attack chains in the confirmed findings."""
    items = _confirmed(correlated)
    chains: list[Chain] = []

    ssrf = _find(items, VulnClass.SSRF)
    command = _find(items, VulnClass.COMMAND_INJECTION)
    ssti = _find(items, VulnClass.TEMPLATE_INJECTION)
    code_injection = _find(items, VulnClass.CODE_INJECTION)
    idor = _find(items, VulnClass.IDOR)
    missing_auth = _find(items, VulnClass.MISSING_AUTH_CHECK)
    open_redirect = _find(items, VulnClass.OPEN_REDIRECT)
    jwt = _find(items, VulnClass.JWT_NONE_ALG)
    mass_assignment = _find(items, VulnClass.MASS_ASSIGNMENT)
    deserialization = _find(items, VulnClass.INSECURE_DESERIALIZATION)
    xxe = _find(items, VulnClass.XXE)
    debug = _find(items, VulnClass.DEBUG_MODE)
    headers = _find(items, VulnClass.MISSING_SECURITY_HEADERS)

    # 1. SSRF -> cloud metadata -> credentials -> anything
    if ssrf:
        chains.append(Chain(
            title="SSRF -> internal services (cloud metadata) -> credential theft",
            severity="CRITICAL",
            steps=[
                "Use the confirmed SSRF to request the cloud metadata endpoint (169.254.169.254) "
                "or other internal-only services from the server's network position.",
                "Collect the issued credentials / service tokens and map which internal APIs they unlock.",
                "Use the obtained credentials against the application and its sibling services.",
            ],
            reasoning=(
                "An SSRF that reaches the host's loopback or link-local network turns a web bug into "
                "access to the internal infrastructure, and cloud metadata services hand out credentials "
                "without any authentication."
            ),
            impact="Compromise of the cloud account or the internal service mesh, and therefore of the whole application.",
            involved=[item.title for item in ssrf],
            references=[
                "OWASP Testing Guide - Testing for SSRF",
                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html",
            ],
        ))

    # 2. IDOR + write capability -> takeover
    if idor:
        write_hint = " (combine with the missing authorisation check to also write data)" if missing_auth else ""
        chains.append(Chain(
            title="IDOR / BOLA -> cross user data access" + write_hint,
            severity="HIGH",
            steps=[
                "Enumerate the object identifiers of the affected collection with an account you own.",
                "Compare the responses for objects owned by other accounts to measure the exposure.",
                "Check whether the same identifier space is accepted by the write endpoints "
                "(PUT/PATCH/DELETE) of the same resource.",
            ],
            reasoning=(
                "The handler does not scope the lookup to the caller, so the identifier is the only "
                "gate. That turns a read bug into a read *and* write bug as soon as the same pattern "
                "is used by the mutating endpoints."
            ),
            impact="Read and possibly modify other users' records, which is often the first step of an account takeover.",
            involved=[item.title for item in idor] + [item.title for item in missing_auth],
        ))

    # 3. Remote code execution
    rce = command + ssti + code_injection + deserialization
    if rce:
        chains.append(Chain(
            title="Remote code execution on the application host",
            severity="CRITICAL",
            steps=[
                "Reproduce the confirmed code execution with the harmless PoC that the report contains.",
                "Determine the privileges of the application process and its network reachability.",
                "Assess the blast radius: credentials in the environment, mounted secrets, internal services.",
            ],
            reasoning=(
                "Command injection, template injection and unsafe deserialisation all give the same "
                "capability: executing code inside the application process. Once there, the machine "
                "is usually not the real boundary - the cloud account and the internal network are."
            ),
            impact="Full compromise of the application host and everything reachable from it.",
            involved=[item.title for item in rce],
        ))

    # 4. Open redirect + OAuth
    if open_redirect:
        chains.append(Chain(
            title="Open redirect -> OAuth token theft / phishing",
            severity="MEDIUM",
            steps=[
                "Check whether the redirect target is used in an OAuth or SSO callback (the redirect_uri).",
                "Verify whether the token or code is delivered in the query string of the redirected URL.",
                "If yes, chain the redirect with a phishing page to obtain the account session.",
            ],
            reasoning=(
                "A redirect that is fully controlled by the request can be used to make a trusted "
                "domain forward the victim (and their credentials) to an attacker controlled site."
            ),
            impact="Session or OAuth token theft leading to account takeover.",
            involved=[item.title for item in open_redirect],
        ))

    # 5. JWT none -> any identity
    if jwt:
        chains.append(Chain(
            title="Unsigned JWT -> impersonate any user or role",
            severity="CRITICAL",
            steps=[
                "Craft a token with the 'none' algorithm and a chosen role claim.",
                "Replay it against the affected endpoints to confirm the claims are trusted.",
                "Escalate to an administrative role and re-test the privileged endpoints.",
            ],
            reasoning=(
                "If the server does not verify the signature it has no authentication at all: the "
                "claims are just data the client provides."
            ),
            impact="Complete authentication bypass and horizontal/vertical privilege escalation.",
            involved=[item.title for item in jwt],
        ))

    # 6. Mass assignment -> privilege escalation
    if mass_assignment:
        chains.append(Chain(
            title="Mass assignment -> privilege escalation",
            severity="HIGH",
            steps=[
                "Send a request with additional fields (role, is_admin, is_staff, verified, balance) "
                "on the affected endpoint.",
                "Check whether the response reflects the injected value, which proves the field was written.",
                "Repeat the request with an elevated role and verify the effect on a low privileged account.",
            ],
            reasoning=(
                "When the whole request body is expanded into the model, the client decides which "
                "columns are written - including the privileged ones."
            ),
            impact="Privilege escalation, fraudulent balance changes or bypassing approval workflows.",
            involved=[item.title for item in mass_assignment],
        ))

    # 7. XXE -> SSRF / file read
    if xxe:
        chains.append(Chain(
            title="XXE -> file disclosure and internal requests",
            severity="HIGH",
            steps=[
                "Use the confirmed entity resolution to read configuration files of the application.",
                "Look for credentials, connection strings and signing keys in the responses.",
                "Chain the result with the other findings (e.g. forged sessions).",
            ],
            reasoning=(
                "An XML parser that resolves external entities is a file read primitive for every "
                "file the application user can read - and often a request primitive as well."
            ),
            impact="Disclosure of secrets and configuration, leading to further compromise.",
            involved=[item.title for item in xxe],
        ))

    # 8. Debug mode + missing headers -> easier exploitation
    if debug and headers:
        chains.append(Chain(
            title="Debug mode + missing security headers -> lower exploitation cost",
            severity="MEDIUM",
            steps=[
                "Compare the error pages of the staging environment with the production environment.",
                "Use the leaked stack traces to map internal code paths and dependencies.",
                "Check whether the leaked details make the other findings easier to exploit.",
            ],
            reasoning=(
                "Debug output and missing browser protections do not create a vulnerability on their "
                "own, but they remove the friction that normally makes exploitation harder."
            ),
            impact="Lower effort and higher success rate for the other findings.",
            involved=[item.title for item in debug] + [item.title for item in headers],
        ))

    # 9. Missing auth + IDOR
    if missing_auth and idor:
        chains.append(Chain(
            title="Unauthenticated write endpoint + IDOR read",
            severity="CRITICAL",
            steps=[
                "Call the mutating endpoint without any credential to confirm it is really open.",
                "Use the identifier space discovered through the IDOR to modify other users' records.",
            ],
            reasoning=(
                "The read side leaks the identifiers and the write side accepts them without any "
                "check, which is a complete data manipulation path with no authentication at all."
            ),
            impact="Unauthenticated modification of production data.",
            involved=[item.title for item in missing_auth] + [item.title for item in idor],
        ))

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    chains.sort(key=lambda c: order.get(c.severity, 4))
    return chains
