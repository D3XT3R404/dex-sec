"""SARIF 2.1.0 export.

SARIF is the standard format for static analysis results.  Exporting to it
means the findings show up **inline in pull requests** (GitHub Code Scanning)
and in the Security tab of VS Code / JetBrains IDEs.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from ..models import CorrelatedFinding, VerificationStatus

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

LEVEL_BY_SEVERITY = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

STATUS_TO_RESULT = {
    VerificationStatus.CONFIRMED_VULNERABLE: "error",
    VerificationStatus.POTENTIAL: "warning",
    VerificationStatus.NOT_REPRODUCIBLE: "none",
    VerificationStatus.ERROR: "none",
    VerificationStatus.SKIPPED: "none",
}


def _rule_id(finding: CorrelatedFinding) -> str:
    return f"DEXSEC/{finding.finding.vuln_class.value}"


def _fingerprint(finding: CorrelatedFinding) -> str:
    material = "|".join([
        finding.finding.vuln_class.value,
        os.path.basename(finding.finding.file),
        finding.finding.code_snippet.strip()[:120],
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def build_sarif(
    correlated: list[CorrelatedFinding],
    project_path: str = "",
    target_url: str = "",
    tool_version: str = "0.3.0",
) -> dict[str, Any]:
    """Build a SARIF document for the given findings."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in correlated:
        rule_id = _rule_id(finding)
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": finding.finding.vuln_class.value.replace("_", " ").title(),
                "shortDescription": {"text": finding.finding.description or finding.finding.vuln_class.value},
                "fullDescription": {"text": finding.impact},
                "help": {"text": finding.remediation_hint},
                "defaultConfiguration": {
                    "level": LEVEL_BY_SEVERITY.get(finding.final_severity.value, "note")
                },
                "properties": {
                    "cwe": finding.finding.cwe,
                    "tags": ["security", "dex-sec", finding.finding.vuln_class.value.lower()],
                },
            }

        location = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": os.path.relpath(finding.finding.file, project_path).replace("\\", "/")
                    if project_path else finding.finding.file.replace("\\", "/"),
                },
                "region": {
                    "startLine": max(finding.finding.line, 1),
                    "snippet": {"text": finding.finding.code_snippet},
                },
            }
        }

        message = f"[{finding.final_severity.value}] {finding.title}"
        if finding.verification and finding.verification.evidence:
            message += f" — {finding.verification.evidence}"

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": STATUS_TO_RESULT.get(finding.status, "note"),
            "message": {"text": message},
            "locations": [location],
            "partialFingerprints": {"dexsecFingerprint": _fingerprint(finding)},
            "properties": {
                "severity": finding.final_severity.value,
                "status": finding.status.value,
                "cwe": finding.finding.cwe,
                "taintVariable": finding.finding.taint_var,
                "remediation": finding.remediation_hint,
            },
        }
        if finding.verification and finding.verification.safe_poc_curl:
            result["properties"]["safePoC"] = finding.verification.safe_poc_curl
        if finding.finding.route:
            result["properties"]["route"] = f"{finding.finding.route.method} {finding.finding.route.path}"

        results.append(result)

    document = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DEX-SEC",
                        "informationUri": "https://github.com/your-org/dex-sec",
                        "version": tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "target": target_url,
                            "projectPath": project_path,
                        },
                    }
                ],
                "results": results,
            }
        ],
    }
    return document


def write_sarif(document: dict[str, Any], path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2)
    return path
