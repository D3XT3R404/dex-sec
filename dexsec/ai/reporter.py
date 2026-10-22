"""Terminal reporting and export helpers."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from ..models import AuditReport, CorrelatedFinding, PatchResult, VerificationStatus

# Windows consoles frequently default to cp1252 which cannot render the
# symbols used in the report. Make the streams lossy UTF-8 safe once, so every
# entry point (python -m dexsec, the `dexsec` console script, the API) works.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

console = Console()

STATUS_STYLE = {
    VerificationStatus.CONFIRMED_VULNERABLE: "bold red",
    VerificationStatus.POTENTIAL: "bold yellow",
    VerificationStatus.NOT_REPRODUCIBLE: "dim",
    VerificationStatus.ERROR: "bold magenta",
    VerificationStatus.SKIPPED: "dim cyan",
}

SEVERITY_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "cyan",
    "INFO": "dim",
}


def banner(target_url: str, project_path: str) -> None:
    console.print(
        Panel(
            f"[bold]DEX-SEC[/bold] — Inside-Out Hybrid Application Security Testing\n"
            f"[dim]Project:[/dim] {project_path}\n"
            f"[dim]Target:[/dim] {target_url}",
            border_style="cyan",
            expand=False,
        )
    )


def phase_header(number: int, title: str) -> None:
    console.print()
    console.rule(f"[bold cyan]PHASE {number} — {title}[/bold cyan]")


def summary_table(correlated: list[CorrelatedFinding]) -> Table:
    table = Table(title="DEX-SEC Results", show_lines=False, header_style="bold magenta")
    table.add_column("#", justify="right", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Status", width=22)
    table.add_column("Vulnerability", width=20)
    table.add_column("Location", overflow="fold")
    for idx, item in enumerate(correlated, start=1):
        style = SEVERITY_STYLE.get(item.final_severity.value, "")
        table.add_row(
            str(idx),
            f"[{style}]{item.final_severity.value}[/{style}]" if style else item.final_severity.value,
            f"[{STATUS_STYLE.get(item.status, '')}]{item.status.value}[/]",
            item.finding.vuln_class.value,
            f"{item.finding.file}:{item.finding.line}"
            + (f"\n→ {item.finding.route.method} {item.finding.route.path}" if item.finding.route else ""),
        )
    return table


def detail_panel(item: CorrelatedFinding) -> None:
    body = (
        f"[bold]Impact:[/bold] {item.impact}\n"
        f"[bold]Remediation:[/bold] {item.remediation_hint}\n"
    )
    if item.verification and item.verification.evidence:
        body += f"\n[bold]Evidence (external verification):[/bold]\n{item.verification.evidence}\n"
    if item.verification and item.verification.safe_poc_curl:
        body += f"\n[bold]Safe PoC:[/bold]\n[green]{item.verification.safe_poc_curl}[/]"
    console.print(Panel(body, title=f"[bold]{item.title}[/bold]", border_style=SEVERITY_STYLE.get(item.final_severity.value, "white").replace("bold ", ""), expand=False))


def show_code(snippet: str, language: str = "python") -> None:
    if snippet.strip():
        console.print(Syntax(snippet, language, theme="monokai", line_numbers=True))


def show_patch(patch: PatchResult) -> None:
    if not patch.diff.strip():
        console.print(f"[yellow]No automatic diff for {patch.finding_ref}: {patch.explanation}[/yellow]")
        return
    console.print(
        Panel(
            f"[bold]{patch.finding_ref}[/bold] [dim](source: {patch.source})[/dim]\n\n"
            f"[green]{patch.diff}[/green]",
            title="Suggested Fix",
            border_style="green",
            expand=False,
        )
    )


def chains_table(chains) -> Table:
    table = Table(title="Attack Chains", show_lines=False, header_style="bold red")
    table.add_column("#", justify="right", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Chain", overflow="fold")
    table.add_column("Impact", overflow="fold")
    for idx, chain in enumerate(chains, start=1):
        style = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}.get(chain.severity, "")
        table.add_row(
            str(idx),
            f"[{style}]{chain.severity}[/]",
            chain.title,
            chain.impact,
        )
    return table


def show_chains(chains) -> None:
    if not chains:
        console.print("[green]No exploitable chains detected between the findings.[/green]")
        return
    console.print(chains_table(chains))
    for idx, chain in enumerate(chains, start=1):
        steps = "\n".join(f"{i}. {step}" for i, step in enumerate(chain.steps, start=1))
        console.print(
            Panel(
                f"[bold]{chain.reasoning}[/bold]\n\n{steps}\n\n[dim]Findings:[/dim] "
                + "\n".join(f"- {item}" for item in chain.involved),
                title=f"Chain {idx}: {chain.title}",
                border_style="red",
                expand=False,
            )
        )


def next_steps_table(steps) -> Table:
    table = Table(title="Recommended Next Steps", show_lines=False, header_style="bold green")
    table.add_column("#", justify="right", style="dim", width=4)
    table.add_column("Priority", width=9)
    table.add_column("Action", overflow="fold")
    table.add_column("Why", overflow="fold")
    for idx, step in enumerate(steps, start=1):
        style = {"HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "dim"}.get(step.priority, "")
        table.add_row(
            str(idx),
            f"[{style}]{step.priority}[/]" if style else step.priority,
            step.title,
            step.rationale,
        )
    return table


def show_next_steps(steps) -> None:
    if not steps:
        console.print("[green]No follow-up actions needed.[/green]")
        return
    console.print(next_steps_table(steps))
    for idx, step in enumerate(steps, start=1):
        if not step.commands:
            continue
        body = "\n".join(f"[green]$[/green] {cmd}" for cmd in step.commands)
        console.print(
            Panel(
                f"[bold]{step.title}[/bold]\n{step.rationale}\n\n{body}",
                title=f"Step {idx}",
                border_style="green",
                expand=False,
            )
        )


def stats_panel(stats: dict) -> None:
    sev = stats.get("by_severity", {})
    classes = stats.get("by_vuln_class", {})
    sev_text = "  ".join(f"[{SEVERITY_STYLE.get(k, '')}]{k}: {v}[/]" for k, v in sev.items()) or "none"
    cls_text = "  ".join(f"{k}: {v}" for k, v in classes.items()) or "none"
    console.print(
        Panel(
            f"[bold]Total findings:[/bold] {stats.get('total', 0)}\n"
            f"[bold]Confirmed exploitable:[/bold] [bold red]{stats.get('confirmed', 0)}[/bold red]\n"
            f"[bold]Potential:[/bold] [yellow]{stats.get('potential', 0)}[/yellow]\n"
            f"[bold]Not reproducible:[/bold] {stats.get('not_reproducible', 0)}\n\n"
            f"[bold]By severity:[/bold] {sev_text}\n"
            f"[bold]By class:[/bold] {cls_text}",
            title="Summary",
            border_style="blue",
            expand=False,
        )
    )


def _ensure_parent(path: str) -> None:
    """Create the parent directory of a report file if it does not exist."""
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)


def export_json(report: AuditReport, path: str) -> None:
    _ensure_parent(path)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report.to_dict(), fh, indent=2, default=str)
    console.print(f"[green]JSON report written to[/green] {path}")


def export_markdown(report: AuditReport, path: str) -> None:
    _ensure_parent(path)
    lines = [
        "# DEX-SEC Security Audit Report",
        "",
        f"- **Target:** `{report.target_url}`",
        f"- **Project:** `{report.project_path}`",
        f"- **Started:** {report.started_at}",
        f"- **Finished:** {report.finished_at}",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "| --- | --- |",
    ]
    for key, value in report.stats.items():
        if isinstance(value, dict):
            value = ", ".join(f"{k}={v}" for k, v in value.items())
        lines.append(f"| {key} | {value} |")
    lines += ["", "## Findings", ""]
    for idx, item in enumerate(report.correlated, start=1):
        lines += [
            f"### {idx}. {item.title}",
            "",
            f"- **Severity:** {item.final_severity.value}",
            f"- **Status:** {item.status.value}",
            f"- **CWE:** {item.finding.cwe}",
            f"- **Impact:** {item.impact}",
            f"- **Remediation:** {item.remediation_hint}",
        ]
        if item.verification and item.verification.evidence:
            lines.append(f"- **Evidence:** {item.verification.evidence}")
        if item.verification and item.verification.safe_poc_curl:
            lines += ["", "Safe PoC:", "", "```bash", item.verification.safe_poc_curl, "```"]
        lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    console.print(f"[green]Markdown report written to[/green] {path}")


def now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
