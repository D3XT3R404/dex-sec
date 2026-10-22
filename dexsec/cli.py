"""DEX-SEC CLI entrypoint.

Usage examples:
    python -m dexsec scan --path ./my-app --target http://localhost:8000
    python -m dexsec scan --path ./my-app --target http://localhost:8000 --report report.md
"""

from __future__ import annotations

import json
import os
import sys
import time

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from . import __version__
from .ai import advisor, apply as diffapply, chaining, html_report, patcher, pdf, reporter, sarif
from .core import baseline as baseline_mod, correlator, notify, output, watcher
from .dast import openapi, verifier
from .models import AuditReport, VerificationStatus
from .sast import scanner

app = typer.Typer(
    name="dexsec",
    help="Inside-out hybrid application security testing: static analysis, safe exploit verification, AI remediation.",
    no_args_is_help=True,
)
console = Console()


def perform_audit(
    root: str,
    target: str = "",
    timeout: float = 8.0,
    skip_dast: bool = False,
    ai_key: str = "",
    ai_provider: str = "openai",
    ai_model: str = "gpt-4o-mini",
    quiet: bool = False,
    include_skipped: bool = False,
) -> AuditReport:
    """Run the complete pipeline and return the audit report.

    This is the shared engine behind `scan`, `fix` and `watch`.
    """
    report_obj = AuditReport(
        project_path=root,
        target_url=target or "(not set - static only)",
        started_at=reporter.now(),
    )

    if not quiet:
        reporter.banner(report_obj.target_url, root)

    # ---------------- PHASE 1: inside
    if not quiet:
        reporter.phase_header(1, "Inside Inspection (Static Analysis)")
    routes, findings, frameworks = scanner.scan_project(root)
    report_obj.routes = routes
    report_obj.findings = findings
    if not quiet:
        console.print(
            f"[green]OK[/green] {len(routes)} route(s) and {len(findings)} tainted sink(s) found. "
            f"Frameworks: {', '.join(frameworks) if frameworks else 'unknown'}"
        )
        for route in routes[:10]:
            console.print(
                f"  [cyan]{route.method}[/cyan] {route.path}  "
                f"[dim]{route.framework} - {os.path.relpath(route.file, root)}:{route.line}[/dim]"
            )

    # ---------------- PHASE 2: outside
    if target and not skip_dast and findings:
        if not quiet:
            reporter.phase_header(2, "Outside Verification (Safe Probes)")
        verifications = verifier.verify_findings(target, findings, timeout=timeout)
        verifications.extend(verifier.verify_base_url(target, timeout=timeout))
        report_obj.verifications = verifications
        confirmed = [v for v in verifications if v.status == VerificationStatus.CONFIRMED_VULNERABLE]
        if not quiet:
            console.print(
                f"[green]OK[/green] {len(verifications)} probe(s) executed, "
                f"[bold red]{len(confirmed)} confirmed exploitable[/bold red]."
            )
    elif not quiet:
        console.print("\n[yellow]No --target supplied: skipping live verification phase.[/yellow]")

    # ---------------- PHASE 3: correlation
    if not quiet:
        reporter.phase_header(3, "Correlation & Risk Ranking")
    report_obj.correlated = correlator.correlate(findings, report_obj.verifications)
    report_obj.correlated.extend(correlator.standalone_findings(report_obj.verifications, findings))
    report_obj.stats = correlator.summarize(report_obj.correlated)
    if not quiet:
        console.print(reporter.summary_table(report_obj.correlated))
        reporter.stats_panel(report_obj.stats)
        for item in report_obj.correlated:
            if item.status in (VerificationStatus.CONFIRMED_VULNERABLE, VerificationStatus.POTENTIAL):
                reporter.detail_panel(item)

    # ---------------- PHASE 4: AI remediation
    actionable = [
        item for item in report_obj.correlated
        if item.status in (VerificationStatus.CONFIRMED_VULNERABLE, VerificationStatus.POTENTIAL)
        or (include_skipped and item.status == VerificationStatus.SKIPPED)
    ]
    if not quiet:
        reporter.phase_header(4, "AI Remediation")
    if actionable:
        api_key = ai_key or os.environ.get("DEXSEC_AI_KEY", "")
        for item in actionable:
            patch = patcher.generate_patch(item, root, api_key=api_key, provider=ai_provider, model=ai_model)
            ok, message = patcher.validate_patch(patch, root)
            patch.explanation += "\n" + (
                f"Patch validation: {'applies cleanly' if ok else 'needs manual review - ' + message[:200]}"
            )
            report_obj.patches.append(patch)
            if not quiet:
                reporter.show_patch(patch)

    # ---------------- PHASE 5: attack chains
    chains = chaining.analyze_chains(report_obj.correlated)
    report_obj.chains = [chain.to_dict() for chain in chains]
    if not quiet:
        reporter.phase_header(5, "Attack Chain Analysis")
        reporter.show_chains(chains)

    # ---------------- PHASE 6: next steps
    steps = advisor.build_next_steps(
        report_obj.correlated,
        target_url=target,
        api_key=ai_key or os.environ.get("DEXSEC_AI_KEY", ""),
        provider=ai_provider,
        model=ai_model,
    )
    report_obj.next_steps = [step.to_dict() for step in steps]
    if not quiet:
        reporter.phase_header(6, "Next Step Advisor")
        reporter.show_next_steps(steps)

    report_obj.finished_at = reporter.now()
    return report_obj


@app.command()
def scan(
    path: str = typer.Option(".", "--path", "-p", help="Path to the project source code."),
    target: str = typer.Option("", "--target", "-t", help="Live base URL of the application to verify against."),
    report: str = typer.Option("", "--report", "-r", help="Write a Markdown report to this path."),
    json_out: str = typer.Option("", "--json", help="Write a JSON report to this path."),
    html_out: str = typer.Option("", "--html", help="Write an interactive HTML report to this path."),
    pdf_out: str = typer.Option("", "--pdf", help="Write an executive summary PDF to this path."),
    sarif_out: str = typer.Option("", "--sarif", help="Write a SARIF report (GitHub Code Scanning / IDE) to this path."),
    patch_out: str = typer.Option("dexsec-fixes.patch", "--patch-out", help="Where to write the suggested unified diff."),
    timeout: float = typer.Option(8.0, "--timeout", help="Per-request timeout in seconds."),
    apply_patches: bool = typer.Option(False, "--apply-patches", help="Ask to apply validated patches to the repository."),
    ai_key: str = typer.Option("", "--ai-key", help="LLM API key for patch generation (falls back to offline heuristics)."),
    ai_provider: str = typer.Option("openai", "--ai-provider", help="openai | anthropic | gemini"),
    ai_model: str = typer.Option("gpt-4o-mini", "--ai-model", help="Model id for patch generation."),
    skip_dast: bool = typer.Option(False, "--skip-dast", help="Only run the static analysis phase."),
    baseline: str = typer.Option("", "--baseline", help="Compare with a previous scan report (JSON)."),
    write_baseline: str = typer.Option("", "--write-baseline", help="Store the current results as a baseline file."),
    notify_url: str = typer.Option("", "--notify", help="Discord/Slack webhook URL for confirmed findings."),
    notify_level: str = typer.Option("CRITICAL", "--notify-level", help="Minimum severity that triggers a notification."),
    out_dir: str = typer.Option("", "--out-dir", help="Folder for the results (default: <dexsec>/hasil-scan/<project>/<timestamp>)."),
    output_format: str = typer.Option("", "--format", help="Machine readable output on stdout: json | sarif | md | html"),
    stdout_output: bool = typer.Option(False, "--stdout", help="Print the report to stdout instead of the rich layout."),
    min_severity: str = typer.Option("", "--min-severity", help="Hide findings below this severity (INFO|LOW|MEDIUM|HIGH|CRITICAL)."),
):
    """Run the full inside-out audit of a project and its live target."""
    root = os.path.abspath(path)
    if not os.path.isdir(root):
        console.print(f"[red]Path not found:[/red] {root}")
        raise typer.Exit(code=1)

    # configuration file provides the defaults
    from . import config as config_mod

    settings = config_mod.Config.load(root)
    target = target or settings.target
    ai_provider = ai_provider if ai_provider != "openai" else settings.ai_provider
    ai_model = ai_model if ai_model != "gpt-4o-mini" else settings.ai_model
    notify_url = notify_url or settings.notify_url
    notify_level = notify_level if notify_level != "CRITICAL" else settings.notify_level
    out_dir = out_dir or settings.output_root
    min_severity = (min_severity or settings.min_severity).upper()
    if settings.exclude:
        scanner.rules.IGNORED_DIRS.update(settings.exclude)

    report_obj = perform_audit(
        root,
        target=target,
        timeout=timeout,
        skip_dast=skip_dast,
        ai_key=ai_key or os.environ.get(settings.ai_key_env, ""),
        ai_provider=ai_provider,
        ai_model=ai_model,
        quiet=bool(output_format or stdout_output),
    )

    if min_severity and min_severity != "INFO":
        order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        threshold = order.get(min_severity, 0)
        report_obj.correlated = [
            item for item in report_obj.correlated
            if order.get(item.final_severity.value, 0) >= threshold
        ]
        report_obj.stats = correlator.summarize(report_obj.correlated)

    if output_format or stdout_output:
        _print_machine_output(report_obj, output_format or "json", root)
        return

    if not report_obj.findings:
        console.print("[green]No risky sinks detected in the code. Nothing to verify.[/green]")

    # ---------------- PHASE 7: report
    reporter.phase_header(7, "Report")
    result_dir = output.run_output_dir(root, out_dir, target)
    console.print(f"[bold]Output folder:[/bold] {result_dir}")

    if any(p.diff.strip() for p in report_obj.patches):
        path_written = patcher.write_patch_file(report_obj.patches, os.path.join(str(result_dir), patch_out))
        console.print(f"[green]OK[/green] Suggested fixes written to [bold]{path_written}[/bold]")
        console.print(f"[dim]Apply with:[/dim] git apply {os.path.basename(path_written)}")
        if apply_patches:
            proc = os.system(f'cd "{root}" && git apply "{path_written}"')
            console.print("[green]Patches applied.[/green]" if proc == 0 else "[red]git apply failed - review the patch manually.[/red]")

    _export(
        report_obj, report, json_out,
        html_out=html_out, pdf_out=pdf_out, sarif_out=sarif_out,
        result_dir=str(result_dir),
    )

    # ---------------- baseline & notification
    if write_baseline:
        saved = baseline_mod.save_baseline(report_obj.correlated, write_baseline, target)
        console.print(f"[green]OK[/green] Baseline written to [bold]{saved}[/bold]")

    if baseline and os.path.isfile(baseline):
        previous = baseline_mod.load_baseline(baseline)
        comparison = baseline_mod.compare(report_obj.correlated, previous)
        console.print(
            f"\n[bold]Baseline comparison[/bold] vs {os.path.basename(baseline)}: "
            f"[red]{len(comparison.new)} baru[/red], "
            f"[yellow]{len(comparison.escalated)} naik severity[/yellow], "
            f"[green]{len(comparison.resolved)} sudah diperbaiki[/green], "
            f"{comparison.unchanged} tidak berubah"
        )
        for item in comparison.regressions:
            console.print(f"  [red]+[/red] [{item.final_severity.value}] {item.title}")
        for entry in comparison.resolved:
            console.print(f"  [green]-[/green] {entry.get('title')}")

    if notify_url:
        level = notify_level.upper()
        order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        threshold = order.get(level, 4)
        to_notify = [
            item for item in report_obj.correlated
            if item.status == VerificationStatus.CONFIRMED_VULNERABLE
            and order.get(item.final_severity.value, 0) >= threshold
        ]
        ok, message = notify.send_webhook(notify_url, to_notify, target)
        console.print(f"[green]OK[/green] {message}" if ok else f"[red]{message}[/red]")


def _export(
    report_obj: AuditReport,
    md_path: str,
    json_path: str,
    html_out: str = "",
    pdf_out: str = "",
    sarif_out: str = "",
    result_dir: str = "",
) -> None:
    """Write the reports.

    When a path is given it is used as-is.  When nothing is given the reports
    land in the dedicated output folder, never inside the scanned project.
    """
    base = result_dir or report_obj.project_path
    if md_path:
        reporter.export_markdown(report_obj, md_path)
    if json_path:
        reporter.export_json(report_obj, json_path)
    if html_out:
        html_report.write_html(report_obj, html_out)
        console.print(f"[green]HTML report written to[/green] {html_out}")
    if pdf_out:
        pdf.write_executive_pdf(report_obj, pdf_out)
        console.print(f"[green]Executive summary PDF written to[/green] {pdf_out}")
    if sarif_out:
        document = sarif.build_sarif(
            report_obj.correlated,
            project_path=report_obj.project_path,
            target_url=report_obj.target_url,
            tool_version=__version__,
        )
        sarif.write_sarif(document, sarif_out)
        console.print(f"[green]SARIF report written to[/green] {sarif_out}")

    if not any([md_path, json_path, html_out, pdf_out, sarif_out]):
        # default: everything in the output folder
        reporter.export_markdown(report_obj, os.path.join(base, "laporan.md"))
        reporter.export_json(report_obj, os.path.join(base, "laporan.json"))
        html_report.write_html(report_obj, os.path.join(base, "laporan.html"))
        pdf.write_executive_pdf(report_obj, os.path.join(base, "ringkasan.pdf"))
        document = sarif.build_sarif(
            report_obj.correlated,
            project_path=report_obj.project_path,
            target_url=report_obj.target_url,
            tool_version=__version__,
        )
        sarif.write_sarif(document, os.path.join(base, "laporan.sarif"))
        console.print(f"[green]All reports written to[/green] {base}")


@app.command()
def fix(
    path: str = typer.Option(".", "--path", "-p", help="Path to the project source code."),
    target: str = typer.Option("", "--target", "-t", help="Live base URL used to confirm the findings."),
    only: str = typer.Option("", "--only", help="Only fix this vulnerability class (e.g. SQL_INJECTION)."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would change without touching any file."),
    no_commit: bool = typer.Option(False, "--no-commit", help="Apply the patches but do not create a git commit."),
    message: str = typer.Option("fix(security): apply DEX-SEC remediation", "--message", "-m", help="Commit message."),
    timeout: float = typer.Option(8.0, "--timeout", help="Per-request timeout in seconds."),
    ai_key: str = typer.Option("", "--ai-key", help="LLM API key for patch generation."),
    ai_provider: str = typer.Option("openai", "--ai-provider", help="openai | anthropic | gemini"),
    ai_model: str = typer.Option("gpt-4o-mini", "--ai-model", help="Model id for patch generation."),
    out_dir: str = typer.Option("", "--out-dir", help="Folder for the results (default: <dexsec>/hasil-scan/...)."),
):
    """Apply the generated fixes and (optionally) commit them.

    Only patches that apply cleanly are used.  The command never touches a
    file it cannot patch, and it never commits anything it did not change.
    """
    root = os.path.abspath(path)
    if not os.path.isdir(root):
        console.print(f"[red]Path not found:[/red] {root}")
        raise typer.Exit(code=1)

    result_dir = output.run_output_dir(root, out_dir, target)
    report_obj = perform_audit(
        root,
        target=target,
        timeout=timeout,
        ai_key=ai_key,
        ai_provider=ai_provider,
        ai_model=ai_model,
        include_skipped=True,
    )

    reporter.phase_header(7, "Applying Fixes")
    console.print(f"[bold]Output folder:[/bold] {result_dir}")
    usable = [p for p in report_obj.patches if p.diff.strip()]
    if only:
        usable = [p for p in usable if only.upper() in p.vuln_class.value.upper()]
    if not usable:
        console.print("[yellow]Tidak ada patch yang bisa diterapkan.[/yellow]")
        return

    applied_files: list[str] = []
    skipped: list[str] = []
    for patch in usable:
        result = diffapply.apply_diff(patch.diff, root, dry_run=dry_run)
        if result.ok and result.applied:
            applied_files.extend(result.applied)
            console.print(f"[green]OK[/green]   {patch.finding_ref}  ({', '.join(result.applied)})")
        else:
            reason = result.failed[0][1] if result.failed else "tidak bisa diterapkan"
            skipped.append(patch.finding_ref)
            console.print(f"[yellow]SKIP[/yellow] {patch.finding_ref}  ({reason})")

    if not applied_files:
        console.print("[yellow]Tidak ada file yang berubah.[/yellow]")
        return

    unique_files = sorted(set(applied_files))
    if dry_run:
        console.print(f"\n[bold]Dry run[/bold]: {len(unique_files)} file akan berubah: {', '.join(unique_files)}")
        console.print("[dim]Jalankan tanpa --dry-run untuk menerapkan.[/dim]")
        return

    console.print(f"\n[green]OK[/green] {len(unique_files)} file diperbarui: {', '.join(unique_files)}")

    if not no_commit:
        in_git = os.path.isdir(os.path.join(root, ".git"))
        if not in_git:
            console.print("[yellow]Bukan git repository - patch diterapkan, commit dilewati.[/yellow]")
            return
        add = os.system(f'cd "{root}" && git add -- {" ".join(chr(34) + f + chr(34) for f in unique_files)}')
        if add != 0:
            console.print("[yellow]git add gagal - patch tetap diterapkan, commit dilewati.[/yellow]")
            return
        commit = os.system(f'cd "{root}" && git commit -m "{message}"')
        if commit == 0:
            console.print(f"[green]OK[/green] commit dibuat: {message}")
        else:
            console.print("[yellow]git commit gagal (periksa user.email/user.name di git config).[/yellow]")


@app.command()
def watch(
    path: str = typer.Option(".", "--path", "-p", help="Path to the project source code."),
    target: str = typer.Option("", "--target", "-t", help="Live base URL of the application."),
    interval: float = typer.Option(2.0, "--interval", help="Seconds between two file system checks."),
    timeout: float = typer.Option(8.0, "--timeout", help="Per-request timeout in seconds."),
):
    """Re-run the audit automatically whenever a source file changes."""
    root = os.path.abspath(path)
    if not os.path.isdir(root):
        console.print(f"[red]Path not found:[/red] {root}")
        raise typer.Exit(code=1)

    def run_scan() -> AuditReport:
        return perform_audit(root, target=target, timeout=timeout, quiet=True)

    watcher.watch(root, run_scan, interval=interval)


@app.command()
def manual(
    online: bool = typer.Option(False, "--online", help="Only show the link to the online documentation."),
    section: str = typer.Option("", "--section", help="Show only the part of the guide that contains this text."),
):
    """Read the offline manual that ships with this installation."""
    from importlib import resources

    online_url = "https://github.com/your-org/dex-sec/blob/main/docs/PANDUAN-OPERASIONAL.md"
    if online:
        console.print(f"[bold]Online documentation:[/bold] {online_url}")
        return
    try:
        text = (resources.files("dexsec") / "manual" / "PANDUAN.md").read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, AttributeError):
        console.print("[yellow]The manual is not bundled with this installation.[/yellow]")
        console.print(f"[bold]Online documentation:[/bold] {online_url}")
        return
    if section:
        lowered = section.lower()
        blocks = text.split("\n## ")
        matched = [block for block in blocks if lowered in block.lower()]
        if not matched:
            console.print(f"[yellow]Section '{section}' not found in the manual.[/yellow]")
            return
        text = "\n## ".join(matched)
    console.print(text)
    console.print(f"\n[dim]Online version: {online_url}[/dim]")


@app.command()
def init(
    scope: str = typer.Option("project", "--scope", help="project | user"),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing configuration file."),
):
    """Create a configuration file with sensible defaults."""
    from . import config as config_mod

    if scope == "user":
        path = config_mod.user_config_path()
    else:
        path = config_mod.project_config_path(os.getcwd())
    config_mod.write_template(path, force=force)
    console.print(f"[green]OK[/green] configuration written to [bold]{path}[/bold]")
    console.print("[dim]Edit it to set your defaults (exclude, target, notifications, AI provider).[/dim]")


@app.command()
def upgrade(
    repo: str = typer.Option("your-org/dex-sec", "--repo", help="GitHub repository that hosts the releases."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Only show what would be done."),
):
    """Check for a newer version and update the standalone executable."""
    from .core import upgrade as upgrade_mod

    ok, message = upgrade_mod.upgrade(repo=repo, dry_run=dry_run)
    console.print(f"[green]OK[/green] {message}" if ok else f"[red]{message}[/red]")


@app.command()
def config(
    path: str = typer.Option(".", "--path", "-p", help="Project path to look for a configuration file."),
):
    """Show the configuration DEX-SEC is using."""
    from . import config as config_mod

    current = config_mod.Config.load(path)
    console.print(json.dumps(current.to_dict(), indent=2))
    if not current.source_path:
        console.print("\n[dim]No configuration file found - defaults are used. "
                      "Create one with: dexsec init[/dim]")


def _print_machine_output(report_obj: AuditReport, output_format: str, root: str) -> None:
    """Print a machine readable report (for CI pipelines and editor plugins)."""
    output_format = output_format.lower()
    if output_format == "json":
        print(json.dumps(report_obj.to_dict(), indent=2, default=str))
    elif output_format == "sarif":
        document = sarif.build_sarif(
            report_obj.correlated,
            project_path=report_obj.project_path,
            target_url=report_obj.target_url,
            tool_version=__version__,
        )
        print(json.dumps(document, indent=2))
    elif output_format in ("md", "markdown"):
        reporter.export_markdown(report_obj, os.devnull) if False else None
        import io
        buffer = io.StringIO()
        original = reporter.console.file
        reporter.console.file = buffer
        reporter.console.print("```markdown")
        reporter.console.print(_markdown_text(report_obj))
        reporter.console.print("```")
        reporter.console.file = original
        print(buffer.getvalue())
    elif output_format == "html":
        print(html_report.build_html(report_obj))
    else:
        raise typer.BadParameter(f"unknown format: {output_format}")


def _markdown_text(report_obj: AuditReport) -> str:
    lines = [
        "# DEX-SEC Security Audit Report",
        "",
        f"- **Target:** `{report_obj.target_url}`",
        f"- **Project:** `{report_obj.project_path}`",
        f"- **Started:** {report_obj.started_at}",
        f"- **Finished:** {report_obj.finished_at}",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "| --- | --- |",
    ]
    for key, value in report_obj.stats.items():
        if isinstance(value, dict):
            value = ", ".join(f"{k}={v}" for k, v in value.items())
        lines.append(f"| {key} | {value} |")
    lines += ["", "## Findings", ""]
    for index, item in enumerate(report_obj.correlated, start=1):
        lines += [
            f"### {index}. {item.title}",
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
    return "\n".join(lines)


@app.command()
def routes(
    path: str = typer.Option(".", "--path", "-p", help="Path to the project source code."),
):
    """List all HTTP routes discovered inside the codebase."""
    root = os.path.abspath(path)
    found = scanner.discover_routes(root)
    console.print(f"[bold]{len(found)}[/bold] route(s) found in [bold]{root}[/bold]")
    for route in found:
        console.print(f"  [cyan]{route.method:6}[/cyan] {route.path}  [dim]{route.framework} — {route.file}:{route.line}[/dim]")


@app.command()
def fuzz(
    spec: str = typer.Option(..., "--spec", "-s", help="Path to an OpenAPI/Swagger document (json/yaml)."),
    target: str = typer.Option(..., "--target", "-t", help="Base URL of the running API."),
    methods: str = typer.Option("GET,HEAD,OPTIONS", "--methods", help="Comma separated methods that may be called."),
    allow_paths: str = typer.Option("", "--allow-paths", help="Only fuzz paths starting with these prefixes (comma separated)."),
    max_requests: int = typer.Option(200, "--max-requests", help="Hard cap on the number of HTTP requests."),
    rate: float = typer.Option(0.2, "--rate", help="Seconds between two requests (rate limiting)."),
    timeout: float = typer.Option(8.0, "--timeout", help="Per request timeout."),
    include_body: bool = typer.Option(False, "--include-body", help="Also fuzz request body fields (POST/PUT)."),
    json_out: str = typer.Option("", "--json", help="Write the results to this JSON file."),
    out_dir: str = typer.Option("", "--out-dir", help="Folder for the results (default: <dexsec>/hasil-scan/...)."),
):
    """Schema driven black-box fuzzing of a REST API (safe, read-only payloads)."""
    if not os.path.isfile(spec):
        console.print(f"[red]Spec not found:[/red] {spec}")
        raise typer.Exit(code=1)

    config = openapi.FuzzConfig(
        spec_path=spec,
        target=target,
        allowed_methods={m.strip().upper() for m in methods.split(",") if m.strip()},
        allowed_paths=[p.strip() for p in allow_paths.split(",") if p.strip()],
        max_requests=max_requests,
        rate_limit=rate,
        timeout=timeout,
        include_body=include_body,
    )

    reporter.phase_header(1, "Schema Driven Fuzzing")
    console.print(
        f"[dim]Spec:[/dim] {spec}\n[dim]Target:[/dim] {target}\n"
        f"[dim]Methods:[/dim] {', '.join(sorted(config.allowed_methods))}  "
        f"[dim]Max requests:[/dim] {config.max_requests}  [dim]Rate:[/dim] {config.rate_limit}s"
    )
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Fuzzing the API with safe payloads...", total=None)
        findings, sent = openapi.run_fuzz(config)
        progress.update(task, completed=True)

    console.print(f"[green]OK[/green] {sent} request(s) sent, {len(findings)} anomaly(ies) detected.")
    if findings:
        table = Table(title="Fuzzing Anomalies", header_style="bold magenta")
        table.add_column("Severity", width=9)
        table.add_column("Type", width=20)
        table.add_column("Endpoint", overflow="fold")
        table.add_column("Detail", overflow="fold")
        for item in findings:
            style = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}.get(item.severity, "")
            table.add_row(
                f"[{style}]{item.severity}[/]",
                item.kind,
                f"{item.method} {item.path} [{item.parameter}]",
                item.detail,
            )
        console.print(table)
        for item in findings:
            console.print(f"[dim]{item.request_example}[/dim]")
    if json_out:
        with open(json_out, "w", encoding="utf-8") as fh:
            json.dump({"requests_sent": sent, "findings": [f.to_dict() for f in findings]}, fh, indent=2)
        console.print(f"[green]JSON results written to[/green] {json_out}")
    else:
        result_dir = output.run_output_dir(spec, out_dir, target)
        path = os.path.join(str(result_dir), "fuzzing.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"requests_sent": sent, "findings": [f.to_dict() for f in findings]}, fh, indent=2)
        console.print(f"[green]JSON results written to[/green] {path}")


@app.command()
def hook(
    install: bool = typer.Option(False, "--install", help="Install the pre-commit hook into .git/hooks."),
    files: list[str] = typer.Option([], "--file", help="Files to analyse (default: staged files)."),
):
    """Pre-commit hook: block commits that introduce HIGH/CRITICAL findings."""
    from . import hooks

    if install:
        try:
            path = hooks.install_hook(os.getcwd())
        except RuntimeError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1)
        console.print(f"[green]Pre-commit hook installed:[/green] {path}")
        return
    code = hooks.run_hook(list(files) or None)
    if code:
        raise typer.Exit(code=code)
    console.print("[green]DEX-SEC: no blocking findings in the staged files.[/green]")


@app.command()
def doctor(
    target: str = typer.Option("", "--target", "-t", help="Optional base URL to check for reachability."),
):
    """Check the installation, the dependencies and the target."""
    import shutil
    import sys

    from . import __version__

    reporter.phase_header(1, "DEX-SEC doctor")
    ok = True

    console.print(f"DEX-SEC version : {__version__}")
    console.print(f"Python          : {sys.version.split()[0]} ({sys.executable})")

    for module in ("rich", "requests", "typer"):
        try:
            __import__(module)
            console.print(f"[green]OK[/green]   dependency '{module}'")
        except ImportError:
            ok = False
            console.print(f"[red]MISSING[/red] dependency '{module}' -> pip install {module}")

    console_script = shutil.which("dexsec")
    if console_script:
        console.print(f"[green]OK[/green]   console script: {console_script}")
    else:
        console.print("[yellow]WARN[/yellow] console script 'dexsec' is not on PATH "
                      "(use `python -m dexsec` or reinstall with pip)")

    if target:
        try:
            import requests

            response = requests.get(target.rstrip("/") + "/", timeout=8)
            console.print(f"[green]OK[/green]   target reachable: {target} (HTTP {response.status_code})")
        except Exception as exc:  # noqa: BLE001
            ok = False
            console.print(f"[red]FAIL[/red]   target not reachable: {target} ({exc})")

    console.print()
    console.print("[green]Everything looks good.[/green]" if ok else "[yellow]Some checks failed.[/yellow]")


@app.command()
def version():
    """Print the DEX-SEC version."""
    console.print(f"DEX-SEC {__version__} — Inside-Out Hybrid Application Security Testing")


def main() -> None:
    # Windows consoles frequently default to cp1252 which cannot render the
    # symbols used in the report. Fall back to a lossy UTF-8 stream.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    app()


if __name__ == "__main__":
    main()
