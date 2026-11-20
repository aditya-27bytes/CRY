"""Scan execution, multi-engine orchestration, and triage reporting."""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from cry import __version__
from cry.config import settings
from cry.exclusions import ExclusionStats
from cry.models import Finding
from cry.reporters.json_reporter import export_json_report
from cry.reporters.markdown import export_markdown_report
from cry.reporters.terminal import print_verdict_report
from cry.scanners.config_audit import scan_configurations
from cry.scanners.dependencies import DependencyScanner, scan_dependencies
from cry.scanners.network import scan_network_code_patterns
from cry.scanners.sast import SASTScanner
from cry.scanners.sast import scan_directory as scan_sast
from cry.scanners.secrets import SecretsScanner
from cry.scanners.secrets import scan_directory as scan_secrets
from cry.triage.engine import TriageEngine


def is_git_repository_url(url: str) -> bool:
    """Check if target string is a remote Git repository URL."""
    u = url.strip().lower()
    return (
        u.startswith(("git@", "git://"))
        or u.endswith(".git")
        or (
            u.startswith(("http://", "https://"))
            and any(domain in u for domain in ("github.com", "gitlab.com", "bitbucket.org"))
        )
    )


def is_http_url(url: str) -> bool:
    """Check if target string is an HTTP/HTTPS URL."""
    return url.strip().lower().startswith(("http://", "https://"))


def run_scan(
    target: str,
    full: bool,
    no_ai: bool,
    json_output: Path | None,
    markdown_output: Path | None,
    model: str | None,
    base_url: str | None,
    api_key: str | None,
    include_vendor: bool,
    include_tests_and_docs: bool,
    console: Console,
    show_all_in_terminal: bool = False,
) -> None:
    """Scan a codebase, single file, or public Git repo for secrets & vulnerabilities."""
    if model or base_url or (api_key is not None):
        settings.override(model=model, base_url=base_url, api_key=api_key)

    start_time = time.time()
    provider_type = "Local (Private)" if settings.is_local_llm() else "Cloud API"

    is_full_scan = full or target.strip().lower() == "full"
    if target.strip().lower() == "full":
        target = "."

    # 1. Handle Remote Git Repository URL
    if is_git_repository_url(target):
        if not shutil.which("git"):
            console.print("[bold red]Error: Git CLI is not installed or not in PATH.[/bold red]")
            console.print("[dim]Install Git or clone the repository locally to scan it.[/dim]")
            return

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            console.print(
                Panel.fit(
                    f"[bold cyan]CRY Security Scanner v{__version__}[/bold cyan]\n"
                    f"Target: [yellow]{target}[/yellow] (Remote Git Repository)\n"
                    f"AI Triage: [green]{'Disabled (--no-ai)' if no_ai else f'{settings.LLM_MODEL} ({provider_type})'}[/green]",
                    border_style="cyan",
                )
            )

            with console.status(f"[bold cyan]Cloning {target} (shallow)...[/bold cyan]"):
                res = subprocess.run(
                    ["git", "clone", "--depth", "1", target, str(temp_path)],
                    capture_output=True,
                    text=True,
                )
                if res.returncode != 0:
                    console.print(
                        f"[bold red]Failed to clone Git repository:[/bold red]\n{res.stderr.strip()}"
                    )
                    return

            _execute_scan(
                scan_dir=temp_path,
                display_target=target,
                no_ai=no_ai,
                json_output=json_output,
                markdown_output=markdown_output,
                start_time=start_time,
                is_full_scan=is_full_scan,
                include_vendor=include_vendor,
                include_tests_and_docs=include_tests_and_docs,
                console=console,
                show_all_in_terminal=show_all_in_terminal,
            )
        return

    # 2. Handle Non-Git Website URL
    if is_http_url(target):
        console.print(
            Panel.fit(
                "[bold yellow]Website URL Detected[/bold yellow]\n\n"
                "CRY specializes in deep static code analysis (SAST) and credential leak detection (Secrets).\n"
                "[cyan]Dynamic Application Security Testing (DAST) for live hosted websites is scheduled for v0.2.0![/cyan]\n\n"
                "To scan this application's source code now, provide its local folder or Git repository URL:\n"
                "  [bold]cry scan https://github.com/your-org/your-repo[/bold]\n"
                "  [bold]cry scan ./local-project-directory[/bold]",
                border_style="yellow",
            )
        )
        return

    # 3. Handle Local File or Directory
    target_path = Path(target).resolve()
    if not target_path.exists():
        console.print(f"[bold red]Target path does not exist: {target}[/bold red]")
        console.print("[dim]Please pass a valid local folder, file path, or public Git URL.[/dim]")
        return

    banner_content = (
        f"[bold cyan]CRY Security Scanner v{__version__} — FULL PROJECT AUDIT[/bold cyan]\n"
        f"Target: [yellow]{target_path}[/yellow] (Whole Project Deep Scan)\n"
        f"Engines: [cyan]Secrets[/cyan] + [cyan]SAST[/cyan] + [cyan]Supply-Chain (SCA)[/cyan] + [cyan]Config & Git[/cyan] + [cyan]Network (SSRF)[/cyan]\n"
        f"AI Triage: [green]{'Disabled (--no-ai)' if no_ai else f'{settings.LLM_MODEL} ({provider_type})'}[/green]"
        if is_full_scan
        else (
            f"[bold cyan]CRY Security Scanner v{__version__}[/bold cyan]\n"
            f"Target: [yellow]{target_path}[/yellow]\n"
            f"AI Triage: [green]{'Disabled (--no-ai)' if no_ai else f'{settings.LLM_MODEL} ({provider_type})'}[/green]"
        )
    )
    console.print(Panel.fit(banner_content, border_style="cyan"))

    if target_path.is_file():
        # Single file scan
        with console.status("[bold cyan]Scanning single file for flaws & secrets...[/bold cyan]"):
            secret_findings = SecretsScanner().scan_file(
                target_path, target_path.parent, include_tests_and_docs=include_tests_and_docs
            )
            sast_findings = SASTScanner().scan_file(
                target_path, target_path.parent, include_tests_and_docs=include_tests_and_docs
            )
            sca_findings = DependencyScanner().scan_file(target_path, target_path.parent)
            net_findings = scan_network_code_patterns(
                target_path, include_tests_and_docs=include_tests_and_docs
            )
        all_findings = secret_findings + sast_findings + sca_findings + net_findings
        console.print(f"  [dim]• Findings detected:[/dim] {len(all_findings)}")

        _run_triage_and_report(
            all_findings=all_findings,
            target_path=target_path.parent,
            display_target=str(target_path),
            no_ai=no_ai,
            json_output=json_output,
            markdown_output=markdown_output,
            start_time=start_time,
            include_tests_and_docs=include_tests_and_docs,
            console=console,
            show_all_findings=show_all_in_terminal,
        )
    else:
        # Directory scan
        _execute_scan(
            scan_dir=target_path,
            display_target=str(target_path),
            no_ai=no_ai,
            json_output=json_output,
            markdown_output=markdown_output,
            start_time=start_time,
            is_full_scan=is_full_scan,
            include_vendor=include_vendor,
            include_tests_and_docs=include_tests_and_docs,
            console=console,
            show_all_in_terminal=show_all_in_terminal,
        )


def _execute_scan(
    scan_dir: Path,
    display_target: str,
    no_ai: bool,
    json_output: Path | None,
    markdown_output: Path | None,
    start_time: float,
    is_full_scan: bool = False,
    include_vendor: bool = False,
    include_tests_and_docs: bool = False,
    console: Console | None = None,
    show_all_in_terminal: bool = False,
) -> None:
    """Internal helper to scan directory and run triage."""
    c = console or Console()
    exclusion_stats = ExclusionStats()
    with c.status("[bold cyan]Scanning for leaked secrets...[/bold cyan]"):
        secret_findings = scan_secrets(
            scan_dir,
            settings.MAX_FILE_SIZE_MB,
            include_vendor=include_vendor,
            stats=exclusion_stats,
            include_tests_and_docs=include_tests_and_docs,
        )
    c.print(f"  [dim]• Secrets scanner:[/dim]        {len(secret_findings)} finding(s)")

    with c.status("[bold cyan]Scanning for code vulnerabilities...[/bold cyan]"):
        sast_findings = scan_sast(
            scan_dir,
            settings.MAX_FILE_SIZE_MB,
            include_vendor=include_vendor,
            stats=exclusion_stats,
            include_tests_and_docs=include_tests_and_docs,
        )
    c.print(f"  [dim]• SAST scanner:[/dim]           {len(sast_findings)} finding(s)")

    all_findings = secret_findings + sast_findings

    if is_full_scan:
        with c.status("[bold cyan]Auditing dependencies & supply-chain manifests...[/bold cyan]"):
            sca_findings = scan_dependencies(scan_dir)
        c.print(f"  [dim]• Supply-chain (SCA):[/dim]     {len(sca_findings)} finding(s)")

        with c.status("[bold cyan]Auditing repository & environment configurations...[/bold cyan]"):
            config_findings = scan_configurations(scan_dir)
        c.print(f"  [dim]• Config & Git auditor:[/dim]   {len(config_findings)} finding(s)")

        with c.status("[bold cyan]Auditing network endpoints & SSRF attack vectors...[/bold cyan]"):
            net_findings = scan_network_code_patterns(
                scan_dir,
                include_vendor=include_vendor,
                stats=exclusion_stats,
                include_tests_and_docs=include_tests_and_docs,
            )
        c.print(f"  [dim]• Network & SSRF scanner:[/dim] {len(net_findings)} finding(s)")

        all_findings = (
            secret_findings + sast_findings + sca_findings + config_findings + net_findings
        )

    if exclusion_stats.total_skipped > 0:
        c.print(
            f"  [dim]• Excluded files:[/dim]         {exclusion_stats.format_summary()} [dim](use --include-vendor to scan)[/dim]"
        )

    _run_triage_and_report(
        all_findings=all_findings,
        target_path=scan_dir,
        display_target=display_target,
        no_ai=no_ai,
        json_output=json_output,
        markdown_output=markdown_output,
        start_time=start_time,
        exclusion_stats=exclusion_stats,
        include_tests_and_docs=include_tests_and_docs,
        console=c,
        show_all_findings=show_all_in_terminal,
    )


def _run_triage_and_report(
    all_findings: list[Finding],
    target_path: Path,
    display_target: str,
    no_ai: bool,
    json_output: Path | None,
    markdown_output: Path | None,
    start_time: float,
    exclusion_stats: ExclusionStats | None = None,
    include_tests_and_docs: bool = False,
    console: Console | None = None,
    show_all_findings: bool = False,
) -> None:
    """Run AI or heuristic triage, print verdict, and export reports."""
    c = console or Console()
    triage_engine = TriageEngine()
    if no_ai:
        report = triage_engine._heuristic_fallback(
            all_findings, target_path, include_tests_and_docs=include_tests_and_docs
        )
    else:
        with c.status("[bold cyan]Performing AI context triage & risk analysis...[/bold cyan]"):
            report = asyncio.run(
                triage_engine.triage_findings(
                    all_findings, target_path, include_tests_and_docs=include_tests_and_docs
                )
            )

    report.target = display_target
    report.scan_duration_seconds = round(time.time() - start_time, 2)
    if exclusion_stats and exclusion_stats.total_skipped > 0:
        report.skipped_files_count = exclusion_stats.total_skipped
        report.skipped_files_summary = exclusion_stats.format_summary()
        if report.skipped_files_summary not in report.summary:
            report.summary += f" [Excluded: {report.skipped_files_summary}.]"

    # Print Report
    print_verdict_report(report, all_findings=show_all_findings)

    # Optional Exports
    if json_output:
        saved_json = export_json_report(report, json_output)
        c.print(f"[dim]JSON report saved to: [cyan]{saved_json}[/cyan][/dim]")

    if markdown_output:
        saved_md = export_markdown_report(report, markdown_output)
        c.print(f"[dim]Markdown report saved to: [cyan]{saved_md}[/cyan][/dim]")
