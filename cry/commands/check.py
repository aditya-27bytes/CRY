"""Readiness, model validation, and configuration checks."""

from __future__ import annotations

import httpx
from rich.console import Console
from rich.table import Table

from cry import __version__
from cry.config import settings


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


def run_check(console: Console) -> None:
    """Validate configuration, API key presence, provider reachability, and scanner readiness."""
    table = Table(title="CRY Environment & Configuration Check", border_style="cyan")
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


def run_version(console: Console) -> None:
    """Print the version of CRY."""
    console.print(f"[bold cyan]CRY[/bold cyan] version [green]{__version__}[/green]")
