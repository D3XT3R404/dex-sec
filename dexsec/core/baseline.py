"""Baseline handling: compare a scan against a previous one.

Purpose: in a pull request the interesting question is not "what is broken"
but "what did *this* change break".  A baseline file holds the previous scan,
and only new or escalated findings are reported.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from ..models import CorrelatedFinding, Severity

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def finding_key(finding: CorrelatedFinding) -> str:
    """A stable identity for a finding (independent of line numbers)."""
    return "|".join([
        finding.finding.vuln_class.value,
        os.path.basename(finding.finding.file),
        (finding.finding.code_snippet or "").strip().splitlines()[0][:80] if finding.finding.code_snippet else "",
    ])


def save_baseline(correlated: list[CorrelatedFinding], path: str, target_url: str = "") -> str:
    """Write the current findings as a baseline file."""
    payload = {
        "version": 1,
        "target": target_url,
        "created": _now(),
        "findings": [
            {
                "key": finding_key(item),
                "vuln_class": item.finding.vuln_class.value,
                "file": item.finding.file,
                "line": item.finding.line,
                "severity": item.final_severity.value,
                "status": item.status.value,
                "title": item.title,
            }
            for item in correlated
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return path


def load_baseline(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


@dataclass
class BaselineComparison:
    new: list[CorrelatedFinding] = field(default_factory=list)
    resolved: list[dict[str, Any]] = field(default_factory=list)
    escalated: list[CorrelatedFinding] = field(default_factory=list)
    unchanged: int = 0
    total_current: int = 0
    total_baseline: int = 0

    @property
    def regressions(self) -> list[CorrelatedFinding]:
        return self.new + self.escalated


def compare(correlated: list[CorrelatedFinding], baseline: dict[str, Any]) -> BaselineComparison:
    """Compare the current findings with a baseline document."""
    previous = {entry["key"]: entry for entry in baseline.get("findings", [])}
    comparison = BaselineComparison(
        total_current=len(correlated),
        total_baseline=len(previous),
    )

    seen: set[str] = set()
    for item in correlated:
        key = finding_key(item)
        seen.add(key)
        old = previous.get(key)
        if old is None:
            comparison.new.append(item)
            continue
        old_rank = SEVERITY_ORDER.get(Severity(old.get("severity", "INFO")), 4)
        new_rank = SEVERITY_ORDER.get(item.final_severity, 4)
        if new_rank < old_rank:
            comparison.escalated.append(item)
        else:
            comparison.unchanged += 1

    for key, entry in previous.items():
        if key not in seen:
            comparison.resolved.append(entry)

    return comparison


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
