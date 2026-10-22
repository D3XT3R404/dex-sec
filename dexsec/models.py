"""Core data models shared across all DEX-SEC modules.

Single source of truth for the data flowing through the pipeline:
    SAST findings -> DAST verification -> Correlation -> AI patch -> Report
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnClass(str, Enum):
    # Injection & code execution
    SQL_INJECTION = "SQL_INJECTION"
    NOSQL_INJECTION = "NOSQL_INJECTION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    CODE_INJECTION = "CODE_INJECTION"
    TEMPLATE_INJECTION = "TEMPLATE_INJECTION"
    XXE = "XXE"
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"
    # Path & file handling
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    EXPOSED_SECRET_FILE = "EXPOSED_SECRET_FILE"
    # Server side request forgery & redirect
    SSRF = "SSRF"
    OPEN_REDIRECT = "OPEN_REDIRECT"
    # Access control
    IDOR = "IDOR"
    MISSING_AUTH_CHECK = "MISSING_AUTH_CHECK"
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT"
    CSRF_MISSING = "CSRF_MISSING"
    # Crypto & session
    WEAK_CRYPTO = "WEAK_CRYPTO"
    INSECURE_RANDOM = "INSECURE_RANDOM"
    JWT_NONE_ALG = "JWT_NONE_ALG"
    # Configuration & misconfiguration
    DEBUG_MODE = "DEBUG_MODE"
    INSECURE_COOKIE = "INSECURE_COOKIE"
    SESSION_FIXATION = "SESSION_FIXATION"
    PERMISSIVE_CORS = "PERMISSIVE_CORS"
    MISSING_SECURITY_HEADERS = "MISSING_SECURITY_HEADERS"
    INSECURE_DEPENDENCY = "INSECURE_DEPENDENCY"
    # Secrets
    HARDCODE_SECRET = "HARDCODE_SECRET"
    # Black box fuzzing
    BLACKBOX_ANOMALY = "BLACKBOX_ANOMALY"
    # Deployment level
    GRAPHQL_INTROSPECTION = "GRAPHQL_INTROSPECTION"
    # Output handling
    XSS = "XSS"
    UNKNOWN = "UNKNOWN"


class VerificationStatus(str, Enum):
    CONFIRMED_VULNERABLE = "CONFIRMED_VULNERABLE"
    POTENTIAL = "POTENTIAL"
    NOT_REPRODUCIBLE = "NOT_REPRODUCIBLE"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


@dataclass
class RouteInfo:
    """A discovered HTTP route inside the codebase."""

    method: str
    path: str
    file: str
    line: int
    framework: str
    params: list[str] = field(default_factory=list)
    handler_body: str = ""
    source_excerpt: str = ""
    handler_params: list[str] = field(default_factory=list)


@dataclass
class CodeFinding:
    """A potential vulnerability located by static analysis."""

    vuln_class: VulnClass
    severity: Severity
    file: str
    line: int
    code_snippet: str
    description: str
    cwe: str = ""
    route: Optional[RouteInfo] = None
    taint_source: str = ""
    taint_var: str = ""
    sink: str = ""
    confidence: float = 0.5
    matched_pattern: str = ""


@dataclass
class VerificationResult:
    """Outcome of an external, non-destructive probe against a live target."""

    vuln_class: VulnClass
    status: VerificationStatus
    target_url: str
    payload: str
    evidence: str
    response_time_ms: float = 0.0
    baseline_time_ms: float = 0.0
    http_status: Optional[int] = None
    response_excerpt: str = ""
    safe_poc_curl: str = ""
    error: str = ""


@dataclass
class PatchResult:
    """Remediation proposal for a confirmed or potential finding."""

    finding_ref: str
    vuln_class: VulnClass
    diff: str
    explanation: str
    source: str = "fallback"
    confidence: float = 0.5


@dataclass
class CorrelatedFinding:
    """A finding after combining internal code knowledge with external proof."""

    finding: CodeFinding
    verification: Optional[VerificationResult]
    final_severity: Severity
    status: VerificationStatus
    title: str
    impact: str
    remediation_hint: str = ""

    @property
    def is_confirmed(self) -> bool:
        return self.verification is not None and self.verification.status == VerificationStatus.CONFIRMED_VULNERABLE


@dataclass
class AuditReport:
    """Full result of a `DEX-SEC scan` run."""

    project_path: str
    target_url: str
    started_at: str
    finished_at: str = ""
    routes: list[RouteInfo] = field(default_factory=list)
    findings: list[CodeFinding] = field(default_factory=list)
    verifications: list[VerificationResult] = field(default_factory=list)
    correlated: list[CorrelatedFinding] = field(default_factory=list)
    patches: list[PatchResult] = field(default_factory=list)
    next_steps: list[dict[str, Any]] = field(default_factory=list)
    chains: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
