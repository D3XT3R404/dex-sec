"""Watch mode: re-run the audit whenever a source file changes.

A small polling watcher (no third-party dependency) that keeps the terminal
output short: it prints only what changed since the previous run.
"""

from __future__ import annotations

import os
import time
from typing import Callable, Iterable

from ..models import AuditReport, CorrelatedFinding, VerificationStatus

IGNORED_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build",
    ".mypy_cache", ".pytest_cache", ".next", ".idea", ".vscode",
}
SOURCE_EXTENSIONS = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".java", ".go", ".rb", ".cs",
    ".kt", ".rs", ".vue", ".svelte", ".env", ".yaml", ".yml", ".json", ".conf",
)


def snapshot(root: str) -> dict[str, float]:
    """Map of file -> mtime for every watched file."""
    result: dict[str, float] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS and not d.startswith(".")]
        for name in filenames:
            if not name.endswith(SOURCE_EXTENSIONS):
                continue
            path = os.path.join(dirpath, name)
            try:
                result[path] = os.path.getmtime(path)
            except OSError:
                continue
    return result


def _keys(findings: Iterable[CorrelatedFinding]) -> set[str]:
    from .baseline import finding_key

    return {finding_key(f) for f in findings}


def watch(
    root: str,
    run_scan: Callable[[], AuditReport],
    interval: float = 2.0,
    max_iterations: int = 0,
) -> int:
    """Watch *root* and re-run *run_scan* whenever a file changes.

    ``max_iterations`` limits the number of scans (used by the tests);
    0 means "run until interrupted".
    """
    print("[dex-sec] watch mode aktif — tekan Ctrl+C untuk berhenti")
    previous_snapshot = snapshot(root)
    report = run_scan()
    previous_findings = _keys(report.correlated)
    _print_summary(report, previous_findings, initial=True)

    iterations = 0
    try:
        while max_iterations == 0 or iterations < max_iterations:
            time.sleep(interval)
            current = snapshot(root)
            changed = [path for path, mtime in current.items() if previous_snapshot.get(path) != mtime]
            removed = [path for path in previous_snapshot if path not in current]
            if not changed and not removed:
                continue
            previous_snapshot = current
            for path in changed[:10]:
                print(f"[dex-sec] berubah: {os.path.relpath(path, root)}")
            report = run_scan()
            current_findings = _keys(report.correlated)
            _print_summary(report, current_findings, previous=previous_findings)
            previous_findings = current_findings
            iterations += 1
    except KeyboardInterrupt:
        print("\n[dex-sec] watch mode dihentikan")
    return 0


def _print_summary(report: AuditReport, findings: set[str], previous: set[str] | None = None,
                   initial: bool = False) -> None:
    confirmed = [c for c in report.correlated if c.status == VerificationStatus.CONFIRMED_VULNERABLE]
    if initial:
        print(f"[dex-sec] {len(report.correlated)} temuan, {len(confirmed)} terkonfirmasi")
        return
    new = findings - (previous or set())
    fixed = (previous or set()) - findings
    if not new and not fixed:
        print("[dex-sec] tidak ada perubahan status temuan")
        return
    for key in sorted(new):
        print(f"[dex-sec] BARU   {key}")
    for key in sorted(fixed):
        print(f"[dex-sec] SELESAI {key}")
    print(f"[dex-sec] total {len(report.correlated)} temuan, {len(confirmed)} terkonfirmasi")
