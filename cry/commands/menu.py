"""Interactive welcome menu, banner, configuration wizard, and CLI cheat sheet."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from cry import __version__
from cry.commands.check import run_check
from cry.commands.eval import run_eval
from cry.commands.net import run_net
from cry.commands.rules import run_list_rules, run_test_rules
from cry.commands.scan import run_scan
from cry.config import settings

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


def print_banner(console: Console) -> None:
    """Print the stylized welcome banner."""
    console.print(BANNER)


def run_guide(console: Console) -> None:
    """Print the quickstart guide and CLI command cheat sheet."""
    guide_table = Table(
        title="CRY CLI Command Reference (v0.4.1)",
        border_style="cyan",
        show_lines=True,
        expand=True,
    )
    guide_table.add_column("Command", style="bold cyan", width=34)
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
        "cry scan --all (-a)",
        "Display all blockers and warnings in terminal without truncation",
        "cry scan . --all",
    )
    guide_table.add_row(
        "cry scan --include-tests-and-docs",
        "Scan test fixtures, mock files, and docs at blocker severity",
        "cry scan --include-tests-and-docs",
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
        "cry eval --real-apps",
        "Run real-world app benchmark against pinned OWASP NodeGoat commit",
        "cry eval --real-apps",
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
        "Validate configuration, API key presence, provider reachability & models",
        "cry check",
    )
    guide_table.add_row("cry guide", "Displays this help cheat sheet", "cry guide")
    guide_table.add_row("cry version", "Prints the current version of CRY", "cry version")

    console.print(guide_table)


def run_configure_wizard(console: Console) -> None:
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


def run_interactive_menu(console: Console) -> None:
    """Interactive terminal menu for guided navigation."""
    while True:
        console.clear()
        print_banner(console)

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
            "[4]", "Configuration Check", "Inspect environment, scanners, and LLM configuration"
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
            run_scan(
                target=target_str,
                full=False,
                no_ai=not use_ai,
                json_output=None,
                markdown_output=None,
                model=None,
                base_url=None,
                api_key=None,
                include_vendor=False,
                include_tests_and_docs=False,
                console=console,
            )
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "2":
            use_ai = Confirm.ask(
                "Enable AI triage reasoning?", default=settings.has_valid_llm_config()
            )
            run_scan(
                target=".",
                full=True,
                no_ai=not use_ai,
                json_output=None,
                markdown_output=None,
                model=None,
                base_url=None,
                api_key=None,
                include_vendor=False,
                include_tests_and_docs=False,
                console=console,
            )
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
                run_net(
                    target=proj_path,
                    footprint=True,
                    deep=False,
                    ports=None,
                    allow_local=False,
                    authorize=False,
                    yes=False,
                    markdown_output=None,
                    console=console,
                )
            elif net_choice == "2":
                loc_target = Prompt.ask(
                    "Enter local target (e.g. localhost, 127.0.0.1:8000)", default="localhost"
                )
                run_net(
                    target=loc_target,
                    footprint=False,
                    deep=False,
                    ports=None,
                    allow_local=True,
                    authorize=False,
                    yes=False,
                    markdown_output=None,
                    console=console,
                )
            elif net_choice == "3":
                pub_target = Prompt.ask("Enter authorized public host (e.g. example.com)")
                is_deep = Confirm.ask(
                    "Enable deep port probe and legacy TLS review?", default=False
                )
                run_net(
                    target=pub_target,
                    footprint=False,
                    deep=is_deep,
                    ports=None,
                    allow_local=False,
                    authorize=False,
                    yes=True,
                    markdown_output=None,
                    console=console,
                )
            elif net_choice == "4":
                auth_target = Prompt.ask("Enter target host to verify proof of control")
                run_net(
                    target=auth_target,
                    footprint=False,
                    deep=False,
                    ports=None,
                    allow_local=False,
                    authorize=True,
                    yes=False,
                    markdown_output=None,
                    console=console,
                )
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "4":
            run_check(console)
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "5":
            bench_type = Prompt.ask(
                "[bold]Select benchmark type[/bold]\n  [1] Single Model / Baseline Benchmark\n  [2] Side-by-Side Multi-Model Comparison",
                choices=["1", "2"],
                default="1",
            )
            if bench_type == "1":
                run_eval(
                    model=None,
                    base_url=None,
                    api_key=None,
                    no_ai=False,
                    compare=None,
                    markdown_output=None,
                    real_apps=False,
                    console=console,
                )
            else:
                models_to_compare = Prompt.ask(
                    "[bold]Enter comma-separated models to benchmark[/bold]",
                    default="openai/gpt-oss-120b,llama-3.3-70b-versatile",
                )
                run_eval(
                    model=None,
                    base_url=None,
                    api_key=None,
                    no_ai=False,
                    compare=models_to_compare,
                    markdown_output=None,
                    real_apps=False,
                    console=console,
                )
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "6":
            run_configure_wizard(console)
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "7":
            rule_action = Prompt.ask(
                "[bold]Select rules action[/bold]\n  [1] List active rules\n  [2] Test & validate rule patterns",
                choices=["1", "2"],
                default="1",
            )
            if rule_action == "1":
                run_list_rules(category=None, console=console)
            else:
                run_test_rules(console)
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "8":
            run_guide(console)
            Prompt.ask("\n[dim]Press Enter to return to menu...[/dim]")

        elif choice == "9":
            console.print("[bold cyan]Happy shipping! 🚀[/bold cyan]")
            break
