"""Network command execution (passive footprint, active probing, domain authorization)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Confirm

from cry.network_auth import (
    get_or_create_authorization,
    verify_target_control,
)
from cry.network_ip import is_internal
from cry.reporters.markdown import export_network_markdown_report
from cry.reporters.terminal import print_network_report
from cry.scanners.network import (
    audit_network_target,
    audit_project_network,
    extract_host_and_port,
    parse_port_list,
)


def run_net(
    target: str,
    footprint: bool,
    deep: bool,
    ports: str | None,
    allow_local: bool,
    authorize: bool,
    yes: bool,
    markdown_output: Path | None,
    console: Console,
) -> None:
    """Perform passive network footprint discovery (default) or authorized live host security analysis."""
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
