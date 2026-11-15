"""Command Line Interface for CRY with interactive welcome menu."""

import asyncio
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from cry import __version__
from cry.config import settings
from cry.models import Finding
from cry.reporters.json_reporter import export_json_report
from cry.reporters.markdown import export_markdown_report, export_network_markdown_report
from cry.reporters.terminal import print_network_report, print_verdict_report
from cry.scanners.config_audit import scan_configurations
from cry.scanners.dependencies import DependencyScanner, scan_dependencies
from cry.scanners.network import audit_network_target, scan_network_code_patterns
from cry.scanners.sast import SASTScanner
from cry.scanners.sast import scan_directory as scan_sast
from cry.scanners.secrets import SecretsScanner
from cry.scanners.secrets import scan_directory as scan_secrets
from cry.triage.client import LLMClient
from cry.triage.engine import TriageEngine

app = typer.Typer(
    name="cry",
    help="CRY: Open-source code security and triage platform for indie developers and small teams.",
    no_args_is_help=False,
)
console = Console()

BANNER = rf"""
[bold cyan]
  ██████╗██████╗ ██╗   ██╗
 ██╔════╝██╔══██╗╚██╗ ██╔╝
 ██║     ██████╔╝ ╚████╔╝ 
 ██║     ██╔══██╗  ╚██╔╝  
 ╚██████╗██║  ██║   ██║   
  ╚═════╝╚═╝  ╚═╝   ╚═╝   
[/bold cyan]
[bold white]Know if you're safe to ship.[/bold white]
[dim]v{__version__} • Open-source security for indie developers & small teams[/dim]
"""


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


def print_banner() -> None:
    """Print the stylized welcome banner."""
    console.print(BANNER)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """CRY entrypoint: launches interactive menu if no command is specified."""
    if ctx.invoked_subcommand is None:
        interactive_menu()


def interactive_menu() -> None:
    """Interactive terminal menu for guided navigation."""
    while True:
        console.clear()
        print_banner()

        provider_badge = (
            "[bold green]Local (Private)[/bold green]"
            if settings.is_local_llm()
            else (
                f"[bold green]Cloud API ({settings.LLM_MODEL})[/bold green]"
                if settings.has_valid_llm_config()
                else "[bold yellow]Offline / Heuristic mode[/bold yellow]"
            )
        )

        console.print(f"  [bold]AI Engine:[/bold] {provider_badge}")
        console.print(
            "  [bold]Scanners:[/bold] [cyan]Secrets[/cyan] + [cyan]SAST[/cyan] + [cyan]Supply-Chain (SCA)[/cyan] + [cyan]Config Audit[/cyan] + [cyan]Network (SSRF)[/cyan]"
        )
        console.print()

        menu_table = Table(
            title="Interactive Menu",
            box=None,
            show_header=False,
            padding=(0, 2),
        )
        menu_table.add_column("Key", style="bold cyan")
        menu_table.add_column("Action", style="bold")
        menu_table.add_column("Description", style="dim")

        menu_table.add_row(
            "[1]", "Quick Scan", "Scan a specific local path (file/folder) or public Git repository URL"
        )
        menu_table.add_row(
            "[2]", "Full Project Audit", "Scan the whole project across all 5 security scanner engines"
        )
        menu_table.add_row(
            "[3]", "Network & IP Intelligence", "Inspect IP records, reverse DNS, SSL/TLS, and HTTP headers"
        )
        menu_table.add_row(
            "[4]", "Health Check", "Inspect environment, scanners, and LLM configuration"
        )
        menu_table.add_row(
            "[5]", "Run Benchmark", "Test accuracy against ground truth (Juice Shop evals)"
        )
        menu_table.add_row("[6]", "Configure LLM", "Set up your Groq / Ollama API key and models")
        menu_table.add_row(
            "[7]", "Quickstart Guide", "Show terminal cheat sheet and CLI usage examples"
        )
        menu_table.add_row("[8]", "Exit", "Close CRY")

        console.print(menu_table)
        console.print()

        try:
            choice = Prompt.ask(
                "[bold cyan]Select an option[/bold cyan]",
                choices=["1", "2", "3", "4", "5", "6", "7", "8"],
                default="1",
            )
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Goodbye![/dim]")
            break

        if choice == "1":
            target_str = Prompt.ask(
                "[bold]Enter local path (file/folder) or public Git URL[/bold]",
                default=".",
            )
            use_ai = Confirm.ask(
                "Enable AI triage reasoning?", default=settings.has_valid_llm_config()
            )
            scan(target=target_str, no_ai=not use_ai, json_output=None, markdown_output=None)
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "2":
            use_ai = Confirm.ask(
                "Enable AI triage reasoning?", default=settings.has_valid_llm_config()
            )
            scan(target=".", full=True, no_ai=not use_ai, json_output=None, markdown_output=None)
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "3":
            net_target = Prompt.ask(
                "[bold]Enter domain name, IP address, or URL to inspect[/bold]",
                default="google.com",
            )
            net(target=net_target, markdown_output=None)
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "4":
            check()
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "5":
            console.print("\n[bold cyan]Running Accuracy Benchmark...[/bold cyan]")
            from evals.runner import load_ground_truth, print_scorecard, score_triage_run

            dataset_file = Path(__file__).parent.parent / "evals" / "datasets" / "ground_truth.json"
            samples_dir = Path(__file__).parent.parent / "evals" / "datasets" / "samples"
            if dataset_file.exists():
                cases = load_ground_truth(dataset_file)
                raw = scan_secrets(samples_dir) + scan_sast(samples_dir)
                triage = TriageEngine()
                rep = triage._heuristic_fallback(raw, samples_dir)
                scorecard = score_triage_run(cases, rep)
                print_scorecard(scorecard)
            else:
                console.print("[yellow]Benchmark dataset not found.[/yellow]")
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "6":
            configure_wizard()
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "7":
            guide()
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "8":
            console.print("[bold cyan]Happy shipping! 🚀[/bold cyan]")
            break


def configure_wizard() -> None:
    """Interactive wizard to configure .env."""
    console.print(Panel("[bold]CRY Configuration Wizard[/bold]", border_style="cyan"))
    env_path = Path.cwd() / ".env"

    current_key = settings.LLM_API_KEY
    masked_key = (
        f"{current_key[:6]}...{current_key[-4:]}" if len(current_key) > 10 else "(not configured)"
    )
    console.print(f"Current API Key: [cyan]{masked_key}[/cyan]")
    console.print(f"Current Base URL: [cyan]{settings.LLM_BASE_URL}[/cyan]")
    console.print(f"Current Model:    [cyan]{settings.LLM_MODEL}[/cyan]\n")

    mode = Prompt.ask(
        "Choose setup mode",
        choices=["groq", "ollama", "custom", "cancel"],
        default="groq",
    )

    if mode == "groq":
        key = Prompt.ask("Enter Groq API Key (from https://console.groq.com)")
        if key:
            content = f"""# CRY Configuration
CRY_LLM_BASE_URL=https://api.groq.com/openai/v1
CRY_LLM_API_KEY={key}
CRY_LLM_MODEL=openai/gpt-oss-120b
"""
            env_path.write_text(content, encoding="utf-8")
            console.print(f"[bold green]Saved configuration to {env_path}[/bold green]")
            # Live verification ping
            with console.status("[bold cyan]Verifying Groq API connection...[/bold cyan]"):
                client = LLMClient(api_key=key, model="openai/gpt-oss-120b")
                try:
                    asyncio.run(
                        client.chat_completion_json(
                            system_prompt="Return JSON: {\"status\": \"ok\"}",
                            user_prompt="ping",
                        )
                    )
                    console.print("[bold green]✅ Groq connection verified successfully![/bold green]")
                except Exception as e:
                    console.print(f"[bold yellow]⚠️ Saved, but verification ping failed: {e}[/bold yellow]")

    elif mode == "ollama":
        model_name = Prompt.ask("Enter local model name in Ollama", default="llama3.3:70b")
        content = f"""# CRY Configuration (Local Ollama)
CRY_LLM_BASE_URL=http://localhost:11434/v1
CRY_LLM_API_KEY=ollama
CRY_LLM_MODEL={model_name}
"""
        env_path.write_text(content, encoding="utf-8")
        console.print(f"[bold green]Saved offline configuration to {env_path}[/bold green]")


@app.command()
def guide() -> None:
    """Print the quickstart guide and CLI command cheat sheet."""
    guide_table = Table(title="CRY CLI Command Reference", border_style="cyan")
    guide_table.add_column("Command", style="bold cyan")
    guide_table.add_column("What it does")
    guide_table.add_column("Example", style="dim")

    guide_table.add_row("cry", "Opens the interactive welcome menu", "cry")
    guide_table.add_row(
        "cry scan <target>", "Scans local folder, file, or public Git URL", "cry scan ./src"
    )
    guide_table.add_row(
        "cry scan full",
        "Deep full-project audit (Secrets + SAST + SCA + Configs)",
        "cry scan full",
    )
    guide_table.add_row(
        "cry full",
        "Alias for full-project audit across the entire codebase",
        "cry full --no-ai",
    )
    guide_table.add_row(
        "cry scan <git_url>",
        "Clones & scans a public Git repository",
        "cry scan https://github.com/OWASP/NodeGoat",
    )
    guide_table.add_row(
        "cry scan <path> --no-ai", "Fast offline scan without calling LLM", "cry scan . --no-ai"
    )
    guide_table.add_row(
        "cry scan <path> -m <file>", "Exports findings to Markdown", "cry scan . -m AUDIT.md"
    )
    guide_table.add_row(
        "cry scan <path> -o <file>", "Exports findings to JSON", "cry scan . -o report.json"
    )
    guide_table.add_row(
        "cry net <target>",
        "Live IP lookup, DNS, SSL/TLS, and HTTP security headers audit",
        "cry net google.com",
    )
    guide_table.add_row("cry check", "Checks system readiness and API keys", "cry check")
    guide_table.add_row("cry guide", "Displays this help cheat sheet", "cry guide")
    guide_table.add_row("cry version", "Prints the current version of CRY", "cry version")

    console.print(guide_table)


@app.command()
def version() -> None:
    """Print the version of CRY."""
    console.print(f"[bold cyan]CRY[/bold cyan] version [green]{__version__}[/green]")


@app.command()
def check() -> None:
    """Check your environment, LLM configuration, and scanner readiness."""
    table = Table(title="CRY Environment Health Check")
    table.add_column("Component", style="bold")
    table.add_column("Status", style="bold")
    table.add_column("Details")

    # Check LLM Endpoint
    if settings.is_local_llm():
        table.add_row(
            "LLM Provider",
            "[green]LOCAL (PRIVATE)[/green]",
            f"Endpoint: {settings.LLM_BASE_URL} | Model: {settings.LLM_MODEL}",
        )
    elif settings.has_valid_llm_config():
        table.add_row(
            "LLM Provider",
            "[green]CLOUD (API)[/green]",
            f"Endpoint: {settings.LLM_BASE_URL} | Model: {settings.LLM_MODEL}",
        )
    else:
        table.add_row(
            "LLM Provider",
            "[yellow]NOT CONFIGURED[/yellow]",
            "Set CRY_LLM_API_KEY in .env (or point CRY_LLM_BASE_URL to "
            "http://localhost:11434/v1 for Ollama)",
        )

    # Scanners status
    table.add_row("Python Engine", "[green]READY[/green]", "Python 3.11+ runtime active")
    table.add_row(
        "Secrets Scanner", "[green]READY[/green]", "Built-in entropy & regex rules (25+ patterns)"
    )
    table.add_row(
        "SAST Engine", "[green]READY[/green]", "Code pattern rules active (SQLi, eval, CORS, etc.)"
    )
    table.add_row(
        "Supply-Chain (SCA)", "[green]READY[/green]", "Dependency manifest auditor (package.json, requirements.txt)"
    )
    table.add_row(
        "Config Auditor", "[green]READY[/green]", "Repository hygiene, .gitignore coverage, and Docker security"
    )

    console.print(table)


@app.command()
def scan(
    target: str = typer.Argument(
        ".",
        help="Local file path, directory path, public Git repository URL, or 'full' for complete project scan",
    ),
    full: bool = typer.Option(
        False,
        "--full",
        "-f",
        help="Perform a comprehensive full-project audit across Secrets, SAST, Supply-Chain (SCA), and Configs",
    ),
    no_ai: bool = typer.Option(
        False,
        "--no-ai",
        help="Skip AI triage and output deep rule-based heuristic findings",
    ),
    json_output: Path | None = typer.Option(
        None,
        "--json",
        "-o",
        help="Path to export report as JSON (e.g. -o cry_report.json)",
    ),
    markdown_output: Path | None = typer.Option(
        None,
        "--markdown",
        "-m",
        help="Path to export report as Markdown (e.g. -m AUDIT.md)",
    ),
) -> None:
    """Scan a codebase, single file, or public Git repo for secrets & vulnerabilities."""
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
                    console.print(f"[bold red]Failed to clone Git repository:[/bold red]\n{res.stderr.strip()}")
                    return

            _execute_scan(
                scan_dir=temp_path,
                display_target=target,
                no_ai=no_ai,
                json_output=json_output,
                markdown_output=markdown_output,
                start_time=start_time,
                is_full_scan=is_full_scan,
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
            secret_findings = SecretsScanner().scan_file(target_path, target_path.parent)
            sast_findings = SASTScanner().scan_file(target_path, target_path.parent)
            sca_findings = DependencyScanner().scan_file(target_path, target_path.parent)
            net_findings = scan_network_code_patterns(target_path)
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
        )


@app.command()
def full(
    no_ai: bool = typer.Option(
        False,
        "--no-ai",
        help="Skip AI triage and output deep rule-based heuristic findings",
    ),
    json_output: Path | None = typer.Option(
        None,
        "--json",
        "-o",
        help="Path to export report as JSON (e.g. -o cry_report.json)",
    ),
    markdown_output: Path | None = typer.Option(
        None,
        "--markdown",
        "-m",
        help="Path to export report as Markdown (e.g. -m AUDIT.md)",
    ),
) -> None:
    """Scan the entire project for all vulnerabilities, secrets, dependencies, and configuration flaws."""
    scan(target=".", full=True, no_ai=no_ai, json_output=json_output, markdown_output=markdown_output)


@app.command()
def net(
    target: str = typer.Argument(
        ...,
        help="Domain name, IP address, or URL to inspect (e.g. google.com, 1.1.1.1, https://api.mysite.com)",
    ),
    markdown_output: Path | None = typer.Option(
        None,
        "--markdown",
        "-m",
        help="Path to export network intelligence report as Markdown (e.g. -m NET_REPORT.md)",
    ),
) -> None:
    """Perform live network security intelligence, IP lookup, SSL/TLS, and HTTP security header audit."""
    with console.status(f"[bold cyan]Running network security audit on {target}...[/bold cyan]"):
        report = audit_network_target(target)

    print_network_report(report)

    if markdown_output:
        out = export_network_markdown_report(report, markdown_output)
        console.print(f"[bold green]Network intelligence report saved to: [cyan]{out}[/cyan][/bold green]\n")


def _execute_scan(
    scan_dir: Path,
    display_target: str,
    no_ai: bool,
    json_output: Path | None,
    markdown_output: Path | None,
    start_time: float,
    is_full_scan: bool = False,
) -> None:
    """Internal helper to scan directory and run triage."""
    with console.status("[bold cyan]Scanning for leaked secrets...[/bold cyan]"):
        secret_findings = scan_secrets(scan_dir, settings.MAX_FILE_SIZE_MB)
    console.print(f"  [dim]• Secrets scanner:[/dim]        {len(secret_findings)} finding(s)")

    with console.status("[bold cyan]Scanning for code vulnerabilities...[/bold cyan]"):
        sast_findings = scan_sast(scan_dir, settings.MAX_FILE_SIZE_MB)
    console.print(f"  [dim]• SAST scanner:[/dim]           {len(sast_findings)} finding(s)")

    all_findings = secret_findings + sast_findings

    if is_full_scan:
        with console.status("[bold cyan]Auditing dependencies & supply-chain manifests...[/bold cyan]"):
            sca_findings = scan_dependencies(scan_dir)
        console.print(f"  [dim]• Supply-chain (SCA):[/dim]     {len(sca_findings)} finding(s)")

        with console.status("[bold cyan]Auditing repository & environment configurations...[/bold cyan]"):
            config_findings = scan_configurations(scan_dir)
        console.print(f"  [dim]• Config & Git auditor:[/dim]   {len(config_findings)} finding(s)")

        with console.status("[bold cyan]Auditing network endpoints & SSRF attack vectors...[/bold cyan]"):
            net_findings = scan_network_code_patterns(scan_dir)
        console.print(f"  [dim]• Network & SSRF scanner:[/dim] {len(net_findings)} finding(s)")

        all_findings = secret_findings + sast_findings + sca_findings + config_findings + net_findings

    _run_triage_and_report(
        all_findings=all_findings,
        target_path=scan_dir,
        display_target=display_target,
        no_ai=no_ai,
        json_output=json_output,
        markdown_output=markdown_output,
        start_time=start_time,
    )


def _run_triage_and_report(
    all_findings: list[Finding],
    target_path: Path,
    display_target: str,
    no_ai: bool,
    json_output: Path | None,
    markdown_output: Path | None,
    start_time: float,
) -> None:
    """Run AI or heuristic triage, print verdict, and export reports."""
    triage_engine = TriageEngine()
    if no_ai:
        report = triage_engine._heuristic_fallback(all_findings, target_path)
    else:
        with console.status(
            "[bold cyan]Performing AI context triage & risk analysis...[/bold cyan]"
        ):
            report = asyncio.run(triage_engine.triage_findings(all_findings, target_path))

    report.target = display_target
    report.scan_duration_seconds = round(time.time() - start_time, 2)

    # Print Report
    print_verdict_report(report)

    # Optional Exports
    if json_output:
        saved_json = export_json_report(report, json_output)
        console.print(f"[dim]JSON report saved to: [cyan]{saved_json}[/cyan][/dim]")

    if markdown_output:
        saved_md = export_markdown_report(report, markdown_output)
        console.print(f"[dim]Markdown report saved to: [cyan]{saved_md}[/cyan][/dim]")


if __name__ == "__main__":
    app()

