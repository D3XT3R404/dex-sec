"""Repository level misconfiguration and secret-file scanning.

These checks look at configuration artefacts that ship with the project
(environment files, Dockerfiles, reverse proxy configs) instead of source code.
They are read-only and never touch the network.
"""

from __future__ import annotations

import fnmatch
import os
import re

from ..models import CodeFinding, Severity, VulnClass
from . import rules

SECRET_FILE_NAMES = {
    ".env", ".env.local", ".env.development", ".env.production", ".env.staging",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".npmrc", ".pypirc",
    "credentials.json", "service-account.json", ".htpasswd", "secrets.yaml",
    "secrets.yml", ".aws/credentials", ".docker/config.json",
}

SECRET_FILE_SUFFIXES = (".pem", ".key", ".pfx", ".p12", ".jks", ".keystore", ".tfstate", ".ovpn")

PLACEHOLDER_VALUES = {
    "", "changeme", "change_me", "your_secret", "yourpassword", "example", "dummy",
    "none", "null", "todo", "xxx", "test", "placeholder", "your-token-here",
    "your_api_key_here", "secret", "password", "changethis", "replace_me",
}


def _is_placeholder(value: str) -> bool:
    value = value.strip().strip("\"'").lower()
    if not value or value in PLACEHOLDER_VALUES:
        return True
    if value.startswith(("{", "<", "%", "$", "{{")):
        return True
    if set(value) <= {"*", "x", "X", ".", "-"}:
        return True
    if "your" in value or "example.com" in value or "changeme" in value:
        return True
    return False


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


def scan_secret_files(root: str) -> list[CodeFinding]:
    """Find credential files that are committed into the project."""
    findings: list[CodeFinding] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in rules.IGNORED_DIRS and not d.startswith(".git")]
        for name in filenames:
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            is_secret = name in SECRET_FILE_NAMES or name.lower().endswith(SECRET_FILE_SUFFIXES)
            if not is_secret:
                continue
            content = _read(path)
            if not content:
                continue
            severity = Severity.HIGH
            description = "Credential or key material found in the repository."
            if name.lower().endswith(".tfstate") or name == "credentials.json":
                description = "Infrastructure state / service-account file committed with the source code."
            findings.append(
                CodeFinding(
                    vuln_class=VulnClass.EXPOSED_SECRET_FILE,
                    severity=severity,
                    file=path,
                    line=1,
                    code_snippet=f"{rel} ({len(content)} bytes)",
                    description=description,
                    cwe="CWE-798",
                    sink=rel,
                    confidence=0.8,
                )
            )
    return findings


def scan_env_files(root: str) -> list[CodeFinding]:
    """Detect populated secrets inside .env style files."""
    findings: list[CodeFinding] = []
    pattern = re.compile(
        r"(?im)^\s*([A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIAL)[A-Z0-9_]*)"
        r"\s*=\s*(?P<value>[^\r\n#]+)"
    )
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in rules.IGNORED_DIRS and not d.startswith(".git")]
        for name in filenames:
            if not (name == ".env" or name.startswith(".env.")):
                continue
            path = os.path.join(dirpath, name)
            content = _read(path)
            for match in pattern.finditer(content):
                value = match.group("value").strip().strip("\"'")
                if _is_placeholder(value):
                    continue
                line_no = content[: match.start()].count("\n") + 1
                findings.append(
                    CodeFinding(
                        vuln_class=VulnClass.EXPOSED_SECRET_FILE,
                        severity=Severity.HIGH,
                        file=path,
                        line=line_no,
                        code_snippet=f"{match.group(1)} = <redacted {len(value)} chars>",
                        description=f"Secret '{match.group(1)}' is committed with a real value in {name}.",
                        cwe="CWE-798",
                        sink=match.group(1),
                        confidence=0.85,
                    )
                )
    return findings


def scan_infrastructure(root: str) -> list[CodeFinding]:
    """Check Dockerfile / nginx style configuration for insecure defaults."""
    findings: list[CodeFinding] = []
    targets = {
        "Dockerfile": rules.DOCKER_RULES,
        "docker-compose.yml": rules.DOCKER_RULES,
        "docker-compose.yaml": rules.DOCKER_RULES,
    }
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in rules.IGNORED_DIRS and not d.startswith(".git")]
        for name in filenames:
            path = os.path.join(dirpath, name)
            content = _read(path)
            if not content:
                continue
            rel = os.path.relpath(path, root)

            if name in targets:
                for vuln_class, severity, pattern in targets[name]:
                    for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                        line_no = content[: match.start()].count("\n") + 1
                        findings.append(
                            CodeFinding(
                                vuln_class=VulnClass(vuln_class),
                                severity=Severity(severity),
                                file=path,
                                line=line_no,
                                code_snippet=match.group(0).strip()[:200],
                                description=f"Insecure configuration found in {name}.",
                                cwe="CWE-16",
                                sink=match.group(0).strip()[:120],
                                confidence=0.6,
                            )
                        )
                if name == "Dockerfile" and not re.search(r"(?im)^\s*USER\s+\S+", content):
                    findings.append(
                        CodeFinding(
                            vuln_class=VulnClass.DEBUG_MODE,
                            severity=Severity.LOW,
                            file=path,
                            line=1,
                            code_snippet=rel,
                            description="Dockerfile does not drop privileges: the container runs as root.",
                            cwe="CWE-250",
                            sink="USER not set",
                            confidence=0.5,
                        )
                    )

            if name.endswith((".conf", ".nginx")) or name in ("nginx.conf", "default.conf"):
                for vuln_class, severity, pattern in rules.NGINX_RULES:
                    for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                        line_no = content[: match.start()].count("\n") + 1
                        findings.append(
                            CodeFinding(
                                vuln_class=VulnClass(vuln_class),
                                severity=Severity(severity),
                                file=path,
                                line=line_no,
                                code_snippet=match.group(0).strip()[:200],
                                description=f"Insecure reverse proxy configuration found in {name}.",
                                cwe="CWE-16",
                                sink=match.group(0).strip()[:120],
                                confidence=0.6,
                            )
                        )
    return findings


def scan_misconfiguration(root: str) -> list[CodeFinding]:
    """Run every repository level configuration check."""
    findings: list[CodeFinding] = []
    findings.extend(scan_env_files(root))
    findings.extend(scan_secret_files(root))
    findings.extend(scan_infrastructure(root))
    return findings
