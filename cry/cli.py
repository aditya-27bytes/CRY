"""Command Line Interface for CRY with interactive welcome menu."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from cry.commands.check import _probe_provider_models, run_check, run_version
from cry.commands.eval import run_eval
from cry.commands.menu import (
    BANNER,
    print_banner,
    run_configure_wizard,
    run_guide,
    run_interactive_menu,
)
from cry.commands.net import run_net
from cry.commands.rules import run_list_rules, run_test_rules
from cry.commands.scan import is_git_repository_url, is_http_url, run_scan

app = typer.Typer(
    name="cry",
    help="CRY: Open-source code security and triage platform for indie developers and small teams.",
    no_args_is_help=False,
)
console = Console()


def _unwrap_param(val: Any, default: Any = None) -> Any:
    """Safely unwrap Typer ParameterInfo when command functions are invoked directly in Python."""
    if isinstance(val, typer.models.ParameterInfo):
        return val.default if val.default is not ... else default
    return val


def interactive_menu() -> None:
    """Interactive terminal menu for guided navigation."""
    run_interactive_menu(console)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """CRY entrypoint: launches interactive menu if no command is specified."""
    if ctx.invoked_subcommand is None:
        interactive_menu()


@app.command("configure")
def configure_wizard() -> None:
    """Interactive wizard to configure LLM API keys and model endpoints in .env."""
    run_configure_wizard(console)


@app.command()
def guide() -> None:
    """Print the quickstart guide and CLI command cheat sheet."""
    run_guide(console)


@app.command()
def version() -> None:
    """Print the version of CRY."""
    run_version(console)


@app.command()
def check() -> None:
    """Validate configuration, API key presence, provider reachability, and scanner readiness."""
    run_check(console)


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
    include_tests_and_docs: bool = typer.Option(
        False,
        "--include-tests-and-docs",
        "--include-tests",
        help="Scan test fixtures, build configs, and documentation files at full blocker severity",
    ),
    all_findings: bool = typer.Option(
        False,
        "--all",
        "-a",
        help="Display all findings in the terminal without truncation",
    ),
) -> None:
    """Scan a codebase, single file, or public Git repo for secrets & vulnerabilities."""
    target_val = str(_unwrap_param(target, "."))
    full_val = bool(_unwrap_param(full, False))
    no_ai_val = bool(_unwrap_param(no_ai, False))
    include_vendor_val = bool(_unwrap_param(include_vendor, False))
    include_tests_and_docs_val = bool(_unwrap_param(include_tests_and_docs, False))
    all_findings_val = bool(_unwrap_param(all_findings, False))
    json_output_val = _unwrap_param(json_output, None)
    markdown_output_val = _unwrap_param(markdown_output, None)
    model_val = _unwrap_param(model, None)
    base_url_val = _unwrap_param(base_url, None)
    api_key_val = _unwrap_param(api_key, None)

    run_scan(
        target=target_val,
        full=full_val,
        no_ai=no_ai_val,
        json_output=json_output_val,
        markdown_output=markdown_output_val,
        model=model_val,
        base_url=base_url_val,
        api_key=api_key_val,
        include_vendor=include_vendor_val,
        include_tests_and_docs=include_tests_and_docs_val,
        console=console,
        show_all_in_terminal=all_findings_val,
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
    include_tests_and_docs: bool = typer.Option(
        False,
        "--include-tests-and-docs",
        "--include-tests",
        help="Scan test fixtures, build configs, and documentation files at full blocker severity",
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
    all_findings: bool = typer.Option(
        False,
        "--all",
        "-a",
        help="Display all findings in the terminal without truncation",
    ),
) -> None:
    """Scan the entire project for all vulnerabilities, secrets, dependencies, and configuration flaws."""
    no_ai_val = bool(_unwrap_param(no_ai, False))
    include_vendor_val = bool(_unwrap_param(include_vendor, False))
    include_tests_and_docs_val = bool(_unwrap_param(include_tests_and_docs, False))
    all_findings_val = bool(_unwrap_param(all_findings, False))
    json_output_val = _unwrap_param(json_output, None)
    markdown_output_val = _unwrap_param(markdown_output, None)
    model_val = _unwrap_param(model, None)
    base_url_val = _unwrap_param(base_url, None)
    api_key_val = _unwrap_param(api_key, None)

    scan(
        target=".",
        full=True,
        no_ai=no_ai_val,
        include_vendor=include_vendor_val,
        include_tests_and_docs=include_tests_and_docs_val,
        all_findings=all_findings_val,
        json_output=json_output_val,
        markdown_output=markdown_output_val,
        model=model_val,
        base_url=base_url_val,
        api_key=api_key_val,
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
    target_val = str(_unwrap_param(target, "."))
    footprint_val = bool(_unwrap_param(footprint, False))
    deep_val = bool(_unwrap_param(deep, False))
    ports_val = _unwrap_param(ports, None)
    allow_local_val = bool(_unwrap_param(allow_local, False))
    authorize_val = bool(_unwrap_param(authorize, False))
    yes_val = bool(_unwrap_param(yes, False))
    markdown_output_val = _unwrap_param(markdown_output, None)

    run_net(
        target=target_val,
        footprint=footprint_val,
        deep=deep_val,
        ports=ports_val,
        allow_local=allow_local_val,
        authorize=authorize_val,
        yes=yes_val,
        markdown_output=markdown_output_val,
        console=console,
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
    real_apps: bool = typer.Option(
        False,
        "--real-apps",
        help="Run ground-truth benchmark against real open-source applications (OWASP NodeGoat)",
    ),
) -> None:
    """Benchmark an AI model or compare multiple models side-by-side on ground-truth security cases."""
    model_val = _unwrap_param(model, None)
    base_url_val = _unwrap_param(base_url, None)
    api_key_val = _unwrap_param(api_key, None)
    no_ai_val = bool(_unwrap_param(no_ai, False))
    compare_val = _unwrap_param(compare, None)
    markdown_output_val = _unwrap_param(markdown_output, None)
    real_apps_val = bool(_unwrap_param(real_apps, False))

    rc = run_eval(
        model=model_val,
        base_url=base_url_val,
        api_key=api_key_val,
        no_ai=no_ai_val,
        compare=compare_val,
        markdown_output=markdown_output_val,
        real_apps=real_apps_val,
        console=console,
    )
    if rc != 0:
        raise typer.Exit(code=rc)


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
    category_val = _unwrap_param(category, None)
    if ctx.invoked_subcommand is None:
        list_rules(category=category_val)


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
    category_val = _unwrap_param(category, None)
    run_list_rules(category=category_val, console=console)


@rules_app.command("test")
def test_rules() -> None:
    """Test all loaded rules for valid regex compilation and test sample matches."""
    run_test_rules(console)


__all__ = [
    "BANNER",
    "_probe_provider_models",
    "app",
    "check",
    "configure_wizard",
    "eval_command",
    "full",
    "guide",
    "interactive_menu",
    "is_git_repository_url",
    "is_http_url",
    "list_rules",
    "net",
    "print_banner",
    "rules_app",
    "rules_callback",
    "scan",
    "test_rules",
    "version",
]

if __name__ == "__main__":
    app()
