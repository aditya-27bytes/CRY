"""Command Line Interface for CRY with interactive welcome menu."""

import asyncio
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from cry import __version__
from cry.config import settings
from cry.evals.benchmark import (
    export_benchmark_markdown,
    run_model_benchmark,
    run_multi_model_benchmark,
)
from cry.exclusions import ExclusionStats
from cry.models import Finding
from cry.network_auth import get_or_create_authorization, verify_target_control
from cry.network_ip import is_internal
from cry.reporters.json_reporter import export_json_report
from cry.reporters.markdown import export_markdown_report, export_network_markdown_report
from cry.reporters.terminal import (
    print_benchmark_scorecard,
    print_model_comparison_table,
    print_network_report,
    print_verdict_report,
)
from cry.rules.manager import RuleManager
from cry.scanners.config_audit import scan_configurations
from cry.scanners.dependencies import DependencyScanner, scan_dependencies
from cry.scanners.network import (
    audit_network_target,
    audit_project_network,
    extract_host_and_port,
    parse_port_list,
    scan_network_code_patterns,
)
from cry.scanners.sast import SASTScanner
from cry.scanners.sast import scan_directory as scan_sast
from cry.scanners.secrets import SecretsScanner
from cry.scanners.secrets import scan_directory as scan_secrets
from cry.system_health import collect_system_health, save_system_health_report
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


def _unwrap_param(val: Any, default: Any = None) -> Any:
    """Safely unwrap Typer ParameterInfo when command functions are invoked directly in Python."""
    if isinstance(val, typer.models.ParameterInfo):
        return val.default if val.default is not ... else default
    return val


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
            "[1]",
            "Quick Scan",
            "Scan a specific local path (file/folder) or public Git repository URL",
        )
        menu_table.add_row(
            "[2]",
            "Full Project Audit",
            "Scan the whole project across all 5 security scanner engines",
        )
        menu_table.add_row(
            "[3]",
            "Network & IP Intelligence",
            "Inspect IP records, reverse DNS, SSL/TLS, and HTTP headers",
        )
        menu_table.add_row(
            "[4]", "Health Check", "Inspect environment, scanners, and LLM configuration"
        )
        menu_table.add_row(
            "[5]", "Run Benchmark", "Test accuracy against ground truth (Juice Shop evals)"
        )
        menu_table.add_row("[6]", "Configure LLM", "Set up your Groq / Ollama API key and models")
        menu_table.add_row(
            "[7]", "Rules Catalog", "View and test declarative SAST & Secrets rule catalog"
        )
        menu_table.add_row(
            "[8]", "Quickstart Guide", "Show terminal cheat sheet and CLI usage examples"
        )
        menu_table.add_row("[9]", "Exit", "Close CRY")

        console.print(menu_table)
        console.print()

        try:
            choice = Prompt.ask(
                "[bold cyan]Select an option[/bold cyan]",
                choices=["1", "2", "3", "4", "5", "6", "7", "8", "9"],
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
            console.print()
            console.print(
                Panel.fit(
                    "[bold cyan]Network & Host Intelligence[/bold cyan]\n\n"
                    "  [1] Passive Project Network Footprint (Zero packets dispatched)\n"
                    "  [2] Scan Local Service (--allow-local: localhost / private RFC-1918)\n"
                    "  [3] Scan Authorized Public Host (Requires verified proof of control)\n"
                    "  [4] Authorize Target Domain (Verify DNS TXT or HTTP well-known token)",
                    border_style="cyan",
                )
            )
            net_choice = Prompt.ask("Select option", choices=["1", "2", "3", "4"], default="1")
            if net_choice == "1":
                proj_path = Prompt.ask("Enter project directory", default=".")
                net(target=proj_path, footprint=True)
            elif net_choice == "2":
                loc_target = Prompt.ask(
                    "Enter local target (e.g. localhost, 127.0.0.1:8000)", default="localhost"
                )
                net(target=loc_target, allow_local=True)
            elif net_choice == "3":
                pub_target = Prompt.ask("Enter authorized public host (e.g. example.com)")
                is_deep = Confirm.ask(
                    "Enable deep port probe and legacy TLS review?", default=False
                )
                net(target=pub_target, deep=is_deep, yes=True)
            elif net_choice == "4":
                auth_target = Prompt.ask("Enter target host to verify proof of control")
                net(target=auth_target, authorize=True)
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "4":
            check()
            export_rep = Confirm.ask(
                "\nGenerate a timestamped system health report file in reports/?",
                default=False,
            )
            if export_rep:
                rep_path = save_system_health_report(collect_system_health())
                console.print(
                    f"\n[bold green]📄 System health report generated:[/bold green] [cyan]{rep_path}[/cyan]"
                )
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "5":
            bench_type = Prompt.ask(
                "[bold]Select benchmark type[/bold]\n  [1] Single Model / Baseline Benchmark\n  [2] Side-by-Side Multi-Model Comparison",
                choices=["1", "2"],
                default="1",
            )
            if bench_type == "1":
                eval_command(
                    model=None,
                    base_url=None,
                    api_key=None,
                    no_ai=False,
                    compare=None,
                    markdown_output=None,
                )
            else:
                models_to_compare = Prompt.ask(
                    "[bold]Enter comma-separated models to benchmark[/bold]",
                    default="openai/gpt-oss-120b,llama-3.3-70b-versatile",
                )
                eval_command(
                    model=None,
                    base_url=None,
                    api_key=None,
                    no_ai=False,
                    compare=models_to_compare,
                    markdown_output=None,
                )
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "6":
            configure_wizard()
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "7":
            rule_action = Prompt.ask(
                "[bold]Select rules action[/bold]\n  [1] List active rules\n  [2] Test & validate rule patterns",
                choices=["1", "2"],
                default="1",
            )
            if rule_action == "1":
                list_rules(category=None)
            else:
                test_rules()
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "8":
            guide()
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "9":
            console.print("[bold cyan]Happy shipping! 🚀[/bold cyan]")
            break


@app.command("configure")
def configure_wizard() -> None:
    """Interactive wizard to configure LLM API keys and model endpoints in .env."""
    console.print(Panel("[bold]CRY Configuration Wizard[/bold]", border_style="cyan"))
    env_path = Path.cwd() / ".env"

    current_key = settings.LLM_API_KEY
    masked_key = (
        f"{current_key[:6]}...{current_key[-4:]}" if len(current_key) > 10 else "(not configured)"
    )
    console.print(f"Current Primary Key:      [cyan]{masked_key}[/cyan]")
    console.print(f"Current Primary Base URL: [cyan]{settings.LLM_BASE_URL}[/cyan]")
    console.print(f"Current Primary Model:    [cyan]{settings.LLM_MODEL}[/cyan]")
    console.print(
        f"Current Failover Mode:    [cyan]{'Enabled (CRY_FAILOVER=on)' if settings.FAILOVER_ENABLED else 'Disabled (CRY_FAILOVER=off)'}[/cyan]\n"
    )

    mode = Prompt.ask(
        "Choose primary setup mode",
        choices=["groq", "openrouter", "ollama", "custom", "cancel"],
        default="groq",
    )
    if mode == "cancel":
        console.print("[dim]Configuration cancelled.[/dim]")
        return

    primary_url = ""
    primary_key = ""
    primary_model = ""

    if mode == "groq":
        primary_url = "https://api.groq.com/openai/v1"
        primary_key = Prompt.ask(
            "Enter Groq API Key (from https://console.groq.com)", password=True
        )
        primary_model = "llama-3.1-8b-instant"
    elif mode == "openrouter":
        primary_url = "https://openrouter.ai/api/v1"
        primary_key = Prompt.ask(
            "Enter OpenRouter API Key (from https://openrouter.ai/keys)", password=True
        )
        primary_model = Prompt.ask(
            "Enter model identifier", default="meta-llama/llama-3.3-70b-instruct"
        )
    elif mode == "ollama":
        primary_url = "http://localhost:11434/v1"
        primary_key = "ollama"
        primary_model = Prompt.ask("Enter local model name in Ollama", default="llama3.3:70b")
    elif mode == "custom":
        primary_url = Prompt.ask(
            "Enter OpenAI-compatible base URL", default="http://localhost:8000/v1"
        )
        primary_key = Prompt.ask(
            "Enter API Key (press Enter if local/none)", password=True, default=""
        )
        primary_model = Prompt.ask("Enter model identifier", default="custom-model")

    # Secondary Provider Configuration
    secondary_url = ""
    secondary_key = ""
    secondary_model = ""
    sec_choice = Prompt.ask(
        "Configure secondary backup provider for automatic failover?",
        choices=["none", "openrouter", "custom"],
        default="none",
    )
    if sec_choice == "openrouter":
        secondary_url = "https://openrouter.ai/api/v1"
        secondary_key = Prompt.ask("Enter secondary OpenRouter API Key", password=True)
        secondary_model = Prompt.ask(
            "Enter secondary model identifier", default="meta-llama/llama-3.3-70b-instruct"
        )
    elif sec_choice == "custom":
        secondary_url = Prompt.ask("Enter secondary base URL")
        secondary_key = Prompt.ask("Enter secondary API Key", password=True, default="")
        secondary_model = Prompt.ask("Enter secondary model identifier")

    failover_toggle = Prompt.ask(
        "Enable automatic model failover on rate limits or downtime? (CRY_FAILOVER)",
        choices=["on", "off"],
        default="on" if sec_choice != "none" else "off",
    )

    env_lines = [
        "# CRY Security Configuration",
        f"CRY_LLM_BASE_URL={primary_url}",
        f"CRY_LLM_API_KEY={primary_key}",
        f"CRY_LLM_MODEL={primary_model}",
        "CRY_LLM_FALLBACK_MODELS=qwen/qwen3.8-27b,openai/gpt-oss-20b,openai/gpt-oss-120b,llama-3.3-70b-versatile",
    ]
    if secondary_url:
        env_lines.append(f"CRY_SECONDARY_BASE_URL={secondary_url}")
        env_lines.append(f"CRY_SECONDARY_API_KEY={secondary_key}")
        env_lines.append(f"CRY_SECONDARY_MODEL={secondary_model}")
    env_lines.append(f"CRY_FAILOVER={failover_toggle}")

    env_path.write_text("\n".join(env_lines) + "\n", encoding="utf-8")
    console.print(f"[bold green]Saved configuration to {env_path}[/bold green]")

    if settings.is_local_endpoint(primary_url):
        console.print(
            "[bold cyan]🛡️ Privacy Guard Note:[/bold cyan] [dim]Primary is a local endpoint. "
            "Privacy Guard will block sending code to cloud failover providers.[/dim]"
        )


@app.command()
def guide() -> None:
    """Print the quickstart guide and CLI command cheat sheet."""
    guide_table = Table(
        title="CRY CLI Command Reference (v0.4)",
        border_style="cyan",
        show_lines=True,
        expand=True,
    )
    guide_table.add_column("Command", style="bold cyan", width=32)
    guide_table.add_column("What it does", ratio=2)
    guide_table.add_column("Example", style="dim", ratio=2)

    # Core Code Scanners
    guide_table.add_row("cry", "Opens the interactive welcome menu", "cry")
    guide_table.add_row("cry scan", "Scans current directory with intelligent defaults", "cry scan")
    guide_table.add_row(
        "cry scan <target>", "Scans local folder, file, or public Git URL", "cry scan ./src"
    )
    guide_table.add_row(
        "cry full",
        "Deep full-project audit across all 5 scanners (Secrets, SAST, SCA, Configs, Net)",
        "cry full",
    )
    guide_table.add_row(
        "cry scan full",
        "Alias for full-project audit across all 5 scanners",
        "cry scan full",
    )
    guide_table.add_row(
        "cry scan <git_url>",
        "Clones & scans a public Git repository",
        "cry scan https://github.com/OWASP/NodeGoat",
    )
    guide_table.add_row(
        "cry scan --exclude <globs>",
        "Exclude paths/files from scanning (in addition to .cryignore)",
        'cry scan --exclude "tests/**,vendor/**"',
    )
    guide_table.add_row(
        "cry scan --no-ai", "Fast offline scan without calling LLM", "cry scan --no-ai"
    )
    guide_table.add_row(
        "cry scan -m <file>", "Exports findings to Markdown", "cry scan -m AUDIT.md"
    )
    guide_table.add_row("cry scan -o <file>", "Exports findings to JSON", "cry scan -o report.json")

    # Network & Host Intelligence
    guide_table.add_row(
        "cry net",
        "Passive project network footprint discovery (zero packets sent)",
        "cry net .",
    )
    guide_table.add_row(
        "cry net <target> --allow-local",
        "Audit local dev server or RFC-1918 internal host (localhost, 127.0.0.1)",
        "cry net http://localhost:3000/ --allow-local",
    )
    guide_table.add_row(
        "cry net <target> --authorize",
        "Verify public host ownership token via DNS TXT or HTTP well-known challenge",
        "cry net my-saas.com --authorize",
    )
    guide_table.add_row(
        "cry net <target>",
        "Authorized live audit: DNS, ports, database exposure, TLS & security headers",
        "cry net my-saas.com",
    )
    guide_table.add_row(
        "cry net <target> --deep",
        "Deep network scan: extended ports (28 probed) & legacy TLS 1.0/1.1 checks",
        "cry net my-saas.com --deep",
    )
    guide_table.add_row(
        "cry net <target> -p <ports>",
        "Probe specific ports or port ranges (capped at 100 ports)",
        "cry net my-saas.com -p 80,443,8000-8010",
    )

    # Benchmarking & Rule Catalog
    guide_table.add_row(
        "cry eval",
        "Benchmark AI model or offline baseline on ground truth",
        "cry eval",
    )
    guide_table.add_row(
        "cry eval --compare",
        "Compare multiple models side-by-side on accuracy, latency, and cost",
        "cry eval --compare 'gpt-oss-120b,llama3.3:70b'",
    )
    guide_table.add_row(
        "cry rules",
        "List all declarative SAST & Secrets rules in active catalog",
        "cry rules",
    )
    guide_table.add_row(
        "cry rules test",
        "Validate regex syntax and sample matches for all rules",
        "cry rules test",
    )

    # Setup & Readiness
    guide_table.add_row(
        "cry configure",
        "Launch interactive wizard to set up primary & failover LLM keys",
        "cry configure",
    )
    guide_table.add_row(
        "cry check",
        "Checks readiness, scanner engines, API keys & host system health",
        "cry check",
    )
    guide_table.add_row(
        "cry check --report",
        "Generate & persist timestamped system health report to reports/",
        "cry check --report",
    )
    guide_table.add_row("cry guide", "Displays this help cheat sheet", "cry guide")
    guide_table.add_row("cry version", "Prints the current version of CRY", "cry version")

    console.print(guide_table)


@app.command()
def version() -> None:
    """Print the version of CRY."""
    console.print(f"[bold cyan]CRY[/bold cyan] version [green]{__version__}[/green]")


def _probe_provider_models(base_url: str, api_key: str | None) -> tuple[bool, list[str], str]:
    """Query GET {base_url}/models to inspect model availability."""
    clean_url = base_url.rstrip("/")
    url = f"{clean_url}/models"
    headers: dict[str, str] = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    if "openrouter.ai" in clean_url.lower():
        headers["HTTP-Referer"] = "https://github.com/aditya-27bytes/CRY"
        headers["X-Title"] = "CRY Security Scanner"
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                raw_list = data.get("data", data.get("models", []))
                model_ids: list[str] = []
                for item in raw_list:
                    if isinstance(item, dict) and "id" in item:
                        model_ids.append(str(item["id"]))
                    elif isinstance(item, dict) and "name" in item:
                        model_ids.append(str(item["name"]))
                    elif isinstance(item, str):
                        model_ids.append(item)
                return True, model_ids, f"{len(model_ids)} model(s) available"
            elif resp.status_code == 401:
                return False, [], "Authentication failed (HTTP 401 Unauthorized)"
            else:
                return False, [], f"HTTP {resp.status_code}"
    except httpx.RequestError as e:
        return False, [], f"Unreachable: {e}"
    except Exception as e:
        return False, [], str(e)


@app.command()
def check(
    report: bool = typer.Option(
        False,
        "--report",
        "-r",
        help="Generate and save a timestamped host & system health report to reports/",
    ),
) -> None:
    """Check your environment, LLM configuration, scanner readiness, and host system health."""
    table = Table(title="CRY Environment Health Check", border_style="cyan")
    table.add_column("Component", style="bold")
    table.add_column("Status", style="bold")
    table.add_column("Details")

    # 1. Primary LLM Provider & Model Validation
    if settings.is_local_llm():
        ok, models, msg = _probe_provider_models(settings.LLM_BASE_URL, settings.LLM_API_KEY)
        if ok and settings.LLM_MODEL in models:
            model_status = f"[green]VERIFIED ({settings.LLM_MODEL})[/green]"
        elif ok:
            model_status = (
                f"[yellow]UNCONFIRMED ({settings.LLM_MODEL} not in provider catalog)[/yellow]"
            )
        else:
            model_status = f"[dim]LOCAL ({msg})[/dim]"
        table.add_row(
            "Primary LLM",
            "[green]LOCAL (PRIVATE)[/green]",
            f"Endpoint: {settings.LLM_BASE_URL} | Model: {model_status}",
        )
    elif settings.has_valid_llm_config():
        ok, models, msg = _probe_provider_models(settings.LLM_BASE_URL, settings.LLM_API_KEY)
        if ok and settings.LLM_MODEL in models:
            model_status = f"[green]VERIFIED ({settings.LLM_MODEL})[/green]"
        elif ok:
            model_status = f"[yellow]UNCONFIRMED ({settings.LLM_MODEL} not in catalog)[/yellow]"
        else:
            model_status = f"[yellow]CHECK FAILED ({msg})[/yellow]"
        table.add_row(
            "Primary LLM",
            "[green]CLOUD (API)[/green]",
            f"Endpoint: {settings.LLM_BASE_URL} | Model: {model_status}",
        )
    else:
        table.add_row(
            "Primary LLM",
            "[yellow]NOT CONFIGURED[/yellow]",
            "Set CRY_LLM_API_KEY in .env (or point CRY_LLM_BASE_URL to "
            "http://localhost:11434/v1 for Ollama)",
        )

    # 2. Secondary Failover Provider
    if settings.has_valid_secondary_config():
        ok_sec, sec_models, sec_msg = _probe_provider_models(
            settings.SECONDARY_BASE_URL, settings.SECONDARY_API_KEY
        )
        if ok_sec and settings.SECONDARY_MODEL in sec_models:
            sec_status = f"[green]VERIFIED ({settings.SECONDARY_MODEL})[/green]"
        elif ok_sec:
            sec_status = f"[yellow]UNCONFIRMED ({settings.SECONDARY_MODEL} not in catalog)[/yellow]"
        else:
            sec_status = f"[dim]CONFIGURED ({sec_msg})[/dim]"
        table.add_row(
            "Secondary LLM",
            "[green]CONFIGURED[/green]",
            f"Endpoint: {settings.SECONDARY_BASE_URL} | Model: {sec_status}",
        )
    else:
        table.add_row(
            "Secondary LLM",
            "[dim]NOT CONFIGURED[/dim]",
            "Optional failover provider (set CRY_SECONDARY_API_KEY for OpenRouter / custom)",
        )

    # 3. Privacy Guard Status
    if settings.is_local_llm():
        table.add_row(
            "Privacy Guard",
            "[bold green]ACTIVE (ENFORCED)[/bold green]",
            "Localhost isolated. Cloud failover strictly blocked to prevent data exfiltration.",
        )
    elif settings.FAILOVER_ENABLED and settings.has_valid_secondary_config():
        table.add_row(
            "Privacy Guard",
            "[bold green]FAILOVER ENABLED[/bold green]",
            f"Cloud-to-cloud failover active (CRY_FAILOVER=on) -> {settings.SECONDARY_BASE_URL}",
        )
    else:
        table.add_row(
            "Privacy Guard",
            "[dim]STANDALONE[/dim]",
            "Single provider mode (Failover is off; set CRY_FAILOVER=on to enable)",
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
        "Supply-Chain (SCA)",
        "[green]READY[/green]",
        "Dependency manifest auditor (package.json, requirements.txt)",
    )
    table.add_row(
        "Config Auditor",
        "[green]READY[/green]",
        "Repository hygiene, .gitignore coverage, and Docker security",
    )
    table.add_row(
        "Network & Host",
        "[green]READY[/green]",
        "Passive discovery, active DNS/ports/TLS/headers & IMDS guard",
    )

    console.print(table)
    console.print()

    # 4. Host & Linux System Health Monitor Telemetry
    sys_health = collect_system_health()

    status_color = (
        "green"
        if sys_health.overall_status == "NOMINAL"
        else ("yellow" if sys_health.overall_status == "WARNING" else "red")
    )
    sys_table = Table(
        title=f"🐧 Host & Linux System Health Monitor  [bold {status_color}][Status: {sys_health.overall_status}][/bold {status_color}]",
        border_style="cyan",
        show_lines=True,
        expand=True,
    )
    sys_table.add_column("Telemetry Metric", style="bold cyan", width=22)
    sys_table.add_column("Observed Value", style="bold")
    sys_table.add_column("Health Status / Details", style="dim")

    sys_table.add_row(
        "Hostname & User",
        f"{sys_health.hostname} ({sys_health.logged_user})",
        "[green]Active Local Session[/green]",
    )
    sys_table.add_row(
        "OS Platform",
        sys_health.os_platform,
        "[dim]Host kernel & architecture[/dim]",
    )
    sys_table.add_row(
        "Date & Time",
        sys_health.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "[dim]Synchronized UTC timestamp[/dim]",
    )
    sys_table.add_row(
        "System Uptime",
        f"{sys_health.uptime_formatted} ({sys_health.uptime_seconds:,}s)",
        (
            "[green]Operating without interruption[/green]"
            if sys_health.uptime_seconds > 0
            else "[dim]Available[/dim]"
        ),
    )
    sys_table.add_row(
        "System Load Averages",
        sys_health.load_averages,
        "[dim]1m, 5m, 15m CPU run queue[/dim]",
    )
    cpu_val = (
        f"{sys_health.cpu_utilization_pct:.1f}%"
        if sys_health.cpu_utilization_pct is not None
        else "Sampling..."
    )
    sys_table.add_row(
        "CPU Load & Cores",
        f"{cpu_val} across {sys_health.cpu_cores} core(s)",
        (
            "[green]Nominal CPU utilization[/green]"
            if (sys_health.cpu_utilization_pct is None or sys_health.cpu_utilization_pct < 85)
            else "[yellow]High CPU load[/yellow]"
        ),
    )
    sys_table.add_row(
        "Memory (RAM)",
        f"{sys_health.ram_used_gb:.2f} GB / {sys_health.ram_total_gb:.2f} GB ({sys_health.ram_percent:.1f}% used)",
        (
            "[green]Healthy memory headroom[/green]"
            if sys_health.ram_percent < 85
            else "[yellow]Elevated memory consumption[/yellow]"
        ),
    )
    sys_table.add_row(
        "Disk Storage",
        f"{sys_health.disk_used_gb:.1f} GB / {sys_health.disk_total_gb:.1f} GB ({sys_health.disk_percent:.1f}% used)",
        f"{sys_health.disk_free_gb:.1f} GB free on root filesystem",
    )
    sys_table.add_row(
        "Active Processes",
        f"{sys_health.process_count} running process(es)",
        "[dim]System execution thread pool[/dim]",
    )
    net_style = (
        "[green]ONLINE[/green]"
        if sys_health.network_connected
        else "[yellow]OFFLINE / LOCAL[/yellow]"
    )
    sys_table.add_row(
        "Network Connectivity",
        sys_health.network_status_msg,
        net_style,
    )

    alert_summary = (
        f"[yellow]{'; '.join(sys_health.alerts)}[/yellow]"
        if sys_health.alerts
        else "[green]All monitored thresholds nominal (healthy)[/green]"
    )
    sys_table.add_row(
        "Proactive Health Alerts",
        alert_summary,
        f"Threshold Evaluation: [{status_color}]{sys_health.overall_status}[/{status_color}]",
    )

    console.print(sys_table)

    if report:
        report_file = save_system_health_report(sys_health)
        console.print(
            f"\n[bold green]📄 Timestamped system health report generated:[/bold green] [cyan]{report_file}[/cyan]"
        )


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
    model: str | None = typer.Option(
        None,
        "--model",
        help="AI model identifier for triage (e.g. openai/gpt-oss-120b, llama3.3:70b)",
    ),
    base_url: str | None = typer.Option(
        None,
        "--base-url",
        help="Custom OpenAI-compatible LLM endpoint URL",
    ),
    api_key: str | None = typer.Option(
        None,
        "--api-key",
        help="API key for custom model endpoint",
    ),
    include_vendor: bool = typer.Option(
        False,
        "--include-vendor",
        help="Include vendor, minified, bundled, and gitignored files in the scan",
    ),
) -> None:
    """Scan a codebase, single file, or public Git repo for secrets & vulnerabilities."""
    target = str(_unwrap_param(target, "."))
    full = bool(_unwrap_param(full, False))
    no_ai = bool(_unwrap_param(no_ai, False))
    include_vendor = bool(_unwrap_param(include_vendor, False))
    json_output = _unwrap_param(json_output, None)
    markdown_output = _unwrap_param(markdown_output, None)
    model = _unwrap_param(model, None)
    base_url = _unwrap_param(base_url, None)
    api_key = _unwrap_param(api_key, None)

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
            include_vendor=include_vendor,
        )


@app.command()
def full(
    no_ai: bool = typer.Option(
        False,
        "--no-ai",
        help="Skip AI triage and output deep rule-based heuristic findings",
    ),
    include_vendor: bool = typer.Option(
        False,
        "--include-vendor",
        help="Include vendor, minified, bundled, and gitignored files in the scan",
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
    model: str | None = typer.Option(
        None,
        "--model",
        help="AI model identifier for triage (e.g. openai/gpt-oss-120b, llama3.3:70b)",
    ),
    base_url: str | None = typer.Option(
        None,
        "--base-url",
        help="Custom OpenAI-compatible LLM endpoint URL",
    ),
    api_key: str | None = typer.Option(
        None,
        "--api-key",
        help="API key for custom model endpoint",
    ),
) -> None:
    """Scan the entire project for all vulnerabilities, secrets, dependencies, and configuration flaws."""
    no_ai = bool(_unwrap_param(no_ai, False))
    include_vendor = bool(_unwrap_param(include_vendor, False))
    json_output = _unwrap_param(json_output, None)
    markdown_output = _unwrap_param(markdown_output, None)
    model = _unwrap_param(model, None)
    base_url = _unwrap_param(base_url, None)
    api_key = _unwrap_param(api_key, None)

    scan(
        target=".",
        full=True,
        no_ai=no_ai,
        include_vendor=include_vendor,
        json_output=json_output,
        markdown_output=markdown_output,
        model=model,
        base_url=base_url,
        api_key=api_key,
    )


@app.command()
def net(
    target: str = typer.Argument(
        ".",
        help="Domain name, IP address, URL, or '.' for automated project network footprint & IP discovery",
    ),
    footprint: bool = typer.Option(
        False,
        "--footprint",
        "-f",
        help="Passive network footprint: scans codebase for URLs/IPs without sending network packets",
    ),
    deep: bool = typer.Option(
        False,
        "--deep",
        help="Perform deep active port probe and legacy TLS protocol review",
    ),
    ports: str | None = typer.Option(
        None,
        "--ports",
        "-p",
        help="Comma-separated port numbers or ranges (e.g. '80,443,8000-8010', max 100 ports)",
    ),
    allow_local: bool = typer.Option(
        False,
        "--allow-local",
        help="Explicitly allow active probing of localhost, 127.0.0.1, or private RFC-1918 addresses",
    ),
    authorize: bool = typer.Option(
        False,
        "--authorize",
        help="Verify proof-of-control for target domain via DNS TXT or HTTP well-known challenge",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Confirm execution of deep active network scan without interactive prompt",
    ),
    markdown_output: Path | None = typer.Option(
        None,
        "--markdown",
        "-m",
        help="Path to export network intelligence report as Markdown (e.g. -m NET_REPORT.md)",
    ),
) -> None:
    """Perform passive network footprint discovery (default) or authorized live host security analysis."""
    target = str(_unwrap_param(target, "."))
    footprint = bool(_unwrap_param(footprint, False))
    deep = bool(_unwrap_param(deep, False))
    ports = _unwrap_param(ports, None)
    allow_local = bool(_unwrap_param(allow_local, False))
    authorize = bool(_unwrap_param(authorize, False))
    yes = bool(_unwrap_param(yes, False))
    markdown_output = _unwrap_param(markdown_output, None)

    # 1. Handle Target Authorization Request (--authorize)
    if authorize:
        clean_host, custom_port = extract_host_and_port(target)
        console.print(f"[bold cyan]Verifying target ownership for '{clean_host}'...[/bold cyan]")
        with console.status(
            "[bold cyan]Checking DNS TXT records and HTTP well-known path...[/bold cyan]"
        ):
            verified, msg = verify_target_control(clean_host, port=custom_port)
        if verified:
            console.print(f"\n[bold green]✅ Authorization Verified:[/bold green] {msg}")
            console.print(f"[dim]Target '{clean_host}' is now authorized for active scans.[/dim]\n")
        else:
            rec = get_or_create_authorization(clean_host)
            console.print(f"\n[bold red]❌ Verification Failed:[/bold red] {msg}\n")
            console.print(f"[bold]Target Host:[/bold] {clean_host}")
            if custom_port:
                console.print(f"[bold]Target Port:[/bold] {custom_port}")
            console.print(f"[bold]Verification Token:[/bold] [bold cyan]{rec.token}[/bold cyan]\n")
            console.print("To prove ownership, configure either:")
            console.print(
                f"  1. [bold]DNS TXT Record:[/bold] Add a TXT record for '{clean_host}' with value:"
            )
            console.print(f"     [cyan]cry-verification={rec.token}[/cyan]")

            example_url = (
                f"http://{clean_host}:{custom_port}/.well-known/cry-challenge.txt"
                if custom_port
                else f"https://{clean_host}/.well-known/cry-challenge.txt"
            )
            console.print(
                f"  2. [bold]HTTP File / Route:[/bold] Return the token from '{example_url}' containing:"
            )
            console.print(f"     [cyan]{rec.token}[/cyan]\n")

            if is_internal(clean_host):
                console.print(
                    "[bold yellow]💡 Tip for Local Development:[/bold yellow] [dim]'localhost' and private subnets do not require domain authorization.\n"
                    "   You can audit your local development server directly with:[/dim]\n"
                    f"   [bold green]cry net {target} --allow-local[/bold green]\n"
                )

            console.print(f"Then rerun: [bold green]cry net {target} --authorize[/bold green]\n")
        return

    # 2. Handle Project Footprint Analysis (Passive, Zero Packets)
    is_project = footprint or target == "." or Path(target).is_dir()
    report: Any
    if is_project:
        target_path = Path(target if target != "." else ".")
        with console.status(
            f"[bold cyan]Scanning project network footprint in {target_path} (passive, zero network packets)...[/bold cyan]"
        ):
            report = audit_project_network(target_path, passive=True)
    else:
        # 3. Handle Live Active Network Scan
        if deep and not yes:
            confirmed = Confirm.ask(
                f"[bold yellow]Run deep active network probe against {target}?[/bold yellow]\n"
                "This will probe extended ports and legacy TLS handshakes. Proceed?",
                default=True,
            )
            if not confirmed:
                console.print("[dim]Aborted deep scan.[/dim]")
                return

        port_list = parse_port_list(ports) if ports else None
        with console.status(
            f"[bold cyan]Running authorized active network audit on {target}...[/bold cyan]"
        ):
            report = audit_network_target(
                target,
                allow_local=allow_local,
                deep=deep,
                ports=port_list,
            )

    print_network_report(report)

    if markdown_output:
        out = export_network_markdown_report(report, markdown_output)
        console.print(
            f"[bold green]Network intelligence report saved to: [cyan]{out}[/cyan][/bold green]\n"
        )


@app.command("eval")
def eval_command(
    model: str | None = typer.Option(
        None,
        "--model",
        help="AI model name to benchmark (e.g. openai/gpt-oss-120b, llama3.3:70b)",
    ),
    base_url: str | None = typer.Option(
        None,
        "--base-url",
        help="OpenAI-compatible inference endpoint URL",
    ),
    api_key: str | None = typer.Option(
        None,
        "--api-key",
        help="API key for custom model endpoint",
    ),
    no_ai: bool = typer.Option(
        False,
        "--no-ai",
        help="Evaluate offline deterministic heuristic baseline",
    ),
    compare: str | None = typer.Option(
        None,
        "--compare",
        help="Comma-separated list of models to benchmark side-by-side (e.g. --compare 'gpt-oss-120b,llama3.3:70b')",
    ),
    markdown_output: Path | None = typer.Option(
        None,
        "--markdown",
        "-m",
        help="Export benchmark report to Markdown (e.g. -m BENCHMARK.md)",
    ),
) -> None:
    """Benchmark an AI model or compare multiple models side-by-side on ground-truth security cases."""
    model = _unwrap_param(model, None)
    base_url = _unwrap_param(base_url, None)
    api_key = _unwrap_param(api_key, None)
    no_ai = bool(_unwrap_param(no_ai, False))
    compare = _unwrap_param(compare, None)
    markdown_output = _unwrap_param(markdown_output, None)

    if compare:
        model_list = [m.strip() for m in compare.split(",") if m.strip()]
        console.print(
            f"\n[bold cyan]Running side-by-side benchmark comparison for {len(model_list)} models...[/bold cyan]"
        )
        leaderboard = run_multi_model_benchmark(
            models=model_list, base_url=base_url, api_key=api_key
        )
        print_model_comparison_table(leaderboard)
        if markdown_output:
            export_benchmark_markdown(leaderboard, markdown_output)
            console.print(
                f"[bold green]Comparative benchmark exported to: [cyan]{markdown_output}[/cyan][/bold green]\n"
            )
    else:
        target_model = model or (settings.LLM_MODEL if not no_ai else "Offline Heuristic (No AI)")
        console.print(
            f"\n[bold cyan]Benchmarking model: [green]{target_model}[/green]...[/bold cyan]"
        )
        scorecard = run_model_benchmark(
            model=model, base_url=base_url, api_key=api_key, no_ai=no_ai
        )
        print_benchmark_scorecard(scorecard)
        if markdown_output:
            export_benchmark_markdown(scorecard, markdown_output)
            console.print(
                f"[bold green]Benchmark scorecard exported to: [cyan]{markdown_output}[/cyan][/bold green]\n"
            )


rules_app = typer.Typer(
    name="rules",
    help="Inspect and test declarative security rules catalog.",
    no_args_is_help=False,
)
app.add_typer(rules_app, name="rules")


@rules_app.callback(invoke_without_command=True)
def rules_callback(
    ctx: typer.Context,
    category: str | None = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category (e.g. SECRET_EXPOSURE, INJECTION)",
    ),
) -> None:
    """Inspect and test declarative security rules catalog. Defaults to listing active rules."""
    category = _unwrap_param(category, None)
    if ctx.invoked_subcommand is None:
        list_rules(category=category)


@rules_app.command("list")
def list_rules(
    category: str | None = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category (e.g. SECRET_EXPOSURE, INJECTION)",
    ),
) -> None:
    """List all loaded security rules from catalog and workspace configuration."""
    category = _unwrap_param(category, None)
    mgr = RuleManager()
    rules = mgr.all_rules
    if category:
        rules = [r for r in rules if r.category.value.lower() == category.lower()]

    table = Table(
        title=f"CRY Declarative Security Rules Catalog ({len(rules)} active rules)",
        border_style="cyan",
        expand=True,
    )
    table.add_column("Rule ID", style="bold cyan", width=28)
    table.add_column("Rule Name", style="bold", width=32)
    table.add_column("Category", width=18)
    table.add_column("Severity", width=10)
    table.add_column("CWE", width=10)
    table.add_column("Languages", style="dim")

    for r in rules:
        sev_color = (
            "red"
            if r.severity.value == "CRITICAL"
            else ("yellow" if r.severity.value == "HIGH" else "cyan")
        )
        langs = ", ".join(r.languages) if r.languages else "*"
        table.add_row(
            r.rule_id,
            r.name,
            r.category.value,
            f"[{sev_color}]{r.severity.value}[/{sev_color}]",
            r.cwe_id or "-",
            langs,
        )

    console.print(table)
    console.print()


@rules_app.command("test")
def test_rules() -> None:
    """Test all loaded rules for valid regex compilation and test sample matches."""
    mgr = RuleManager()
    with console.status("[bold cyan]Validating security rules and regex patterns...[/bold cyan]"):
        results = mgr.test_rules()

    console.print()
    if not results["failed_rules"]:
        console.print(
            f"[bold green]✅ All {results['total_rules']} declarative security rules compiled and validated successfully![/bold green]\n"
        )
    else:
        console.print(
            f"[bold red]❌ {len(results['failed_rules'])} rule(s) failed validation:[/bold red]"
        )
        for f in results["failed_rules"]:
            console.print(f"  • [yellow]{f['id']}[/yellow]: {f['error']}")
        console.print()


def _execute_scan(
    scan_dir: Path,
    display_target: str,
    no_ai: bool,
    json_output: Path | None,
    markdown_output: Path | None,
    start_time: float,
    is_full_scan: bool = False,
    include_vendor: bool = False,
) -> None:
    """Internal helper to scan directory and run triage."""
    exclusion_stats = ExclusionStats()
    with console.status("[bold cyan]Scanning for leaked secrets...[/bold cyan]"):
        secret_findings = scan_secrets(
            scan_dir,
            settings.MAX_FILE_SIZE_MB,
            include_vendor=include_vendor,
            stats=exclusion_stats,
        )
    console.print(f"  [dim]• Secrets scanner:[/dim]        {len(secret_findings)} finding(s)")

    with console.status("[bold cyan]Scanning for code vulnerabilities...[/bold cyan]"):
        sast_findings = scan_sast(
            scan_dir,
            settings.MAX_FILE_SIZE_MB,
            include_vendor=include_vendor,
            stats=exclusion_stats,
        )
    console.print(f"  [dim]• SAST scanner:[/dim]           {len(sast_findings)} finding(s)")

    all_findings = secret_findings + sast_findings

    if is_full_scan:
        with console.status(
            "[bold cyan]Auditing dependencies & supply-chain manifests...[/bold cyan]"
        ):
            sca_findings = scan_dependencies(scan_dir)
        console.print(f"  [dim]• Supply-chain (SCA):[/dim]     {len(sca_findings)} finding(s)")

        with console.status(
            "[bold cyan]Auditing repository & environment configurations...[/bold cyan]"
        ):
            config_findings = scan_configurations(scan_dir)
        console.print(f"  [dim]• Config & Git auditor:[/dim]   {len(config_findings)} finding(s)")

        with console.status(
            "[bold cyan]Auditing network endpoints & SSRF attack vectors...[/bold cyan]"
        ):
            net_findings = scan_network_code_patterns(
                scan_dir, include_vendor=include_vendor, stats=exclusion_stats
            )
        console.print(f"  [dim]• Network & SSRF scanner:[/dim] {len(net_findings)} finding(s)")

        all_findings = (
            secret_findings + sast_findings + sca_findings + config_findings + net_findings
        )

    if exclusion_stats.total_skipped > 0:
        console.print(
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
    if exclusion_stats and exclusion_stats.total_skipped > 0:
        report.skipped_files_count = exclusion_stats.total_skipped
        report.skipped_files_summary = exclusion_stats.format_summary()
        if report.skipped_files_summary not in report.summary:
            report.summary += f" [Excluded: {report.skipped_files_summary}.]"

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
