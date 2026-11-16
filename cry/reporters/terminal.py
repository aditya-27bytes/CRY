"""Terminal reporting for CRY scan and triage verdicts."""

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cry.models import Verdict, VerdictReport

console = Console()


def print_verdict_report(report: VerdictReport) -> None:
    """Render a comprehensive, developer-friendly terminal report."""
    console.print()

    # 1. Headline Verdict Banner
    if report.verdict == Verdict.DONT_SHIP:
        verdict_badge = "[bold white on red]  DON'T SHIP  [/bold white on red]"
        border_style = "red"
        headline = "[bold red]CRITICAL SECURITY BLOCKERS DETECTED[/bold red]"
    elif report.verdict == Verdict.FIX_FIRST:
        verdict_badge = "[bold black on yellow]  FIX FIRST  [/bold black on yellow]"
        border_style = "yellow"
        headline = "[bold yellow]SECURITY WARNINGS FOUND — FIX BEFORE PRODUCTION[/bold yellow]"
    else:
        verdict_badge = "[bold white on green]  SAFE TO SHIP  [/bold white on green]"
        border_style = "green"
        headline = "[bold green]NO BLOCKERS FOUND — YOUR APP IS SAFE TO SHIP[/bold green]"

    model_info = (
        f"\n[bold]Triage Engine:[/bold] [cyan]{report.model_used}[/cyan]"
        if report.model_used
        else ""
    )
    failover_info = ""
    if report.model_switches:
        failover_info = "\n[bold yellow]⚡ Multi-Model Resilience:[/bold yellow]\n" + "\n".join(
            f"  • [dim yellow]{sw}[/dim yellow]" for sw in report.model_switches
        )

    console.print(
        Panel(
            f"{verdict_badge}  {headline}\n\n"
            f"[bold]Target:[/bold] [cyan]{report.target}[/cyan]{model_info}{failover_info}\n"
            f"[bold]Summary:[/bold] {report.summary}",
            title="CRY Security Verdict",
            border_style=border_style,
        )
    )

    # 2. Blockers Section (Must Fix)
    if report.blockers:
        console.print()
        table = Table(
            title=f"🚨 Critical Blockers ({len(report.blockers)} issue{'s' if len(report.blockers) != 1 else ''})",
            border_style="red",
            show_lines=True,
            expand=True,
        )
        table.add_column("#", width=3, style="dim")
        table.add_column("Rule & Flaw", style="bold red", width=22)
        table.add_column("Location", style="cyan", width=22)
        table.add_column("Plain-English Explanation & Fix", ratio=1)

        for idx, item in enumerate(report.blockers, 1):
            f = item.finding
            loc = f"{f.file_path}:{f.line_start}" if f.file_path else "—"
            cwe_str = f" ({f.cwe_id})" if f.cwe_id else ""
            rule_header = f"{f.title}{cwe_str}\n[dim]Tool: {f.tool}[/dim]"

            details: list[str] = [
                f"[bold]Problem:[/bold] {item.plain_english_explanation}",
            ]
            if f.code_snippet:
                details.append(
                    f"[bold red]🔴 Vulnerable Code:[/bold red]\n[red]   {f.code_snippet}[/red]"
                )

            if item.exploitability_reasoning:
                details.append(
                    f"[bold red]🛡️ Threat Analysis & Attack Vector:[/bold red] {item.exploitability_reasoning}"
                )

            details.append(f"[bold green]💡 How to fix:[/bold green] {item.fix_recommendation}")

            if item.suggested_replacement_code:
                details.append(
                    f"[bold green]🟢 Replacement Code:[/bold green]\n[green]   {item.suggested_replacement_code}[/green]"
                )

            table.add_row(str(idx), rule_header, loc, "\n".join(details))

        console.print(table)

    # 3. Warnings Section
    if report.warnings:
        console.print()
        table = Table(
            title=f"⚠️ Warnings & Fixes ({len(report.warnings)} item{'s' if len(report.warnings) != 1 else ''})",
            border_style="yellow",
            show_lines=True,
            expand=True,
        )
        table.add_column("#", width=3, style="dim")
        table.add_column("Issue", style="bold yellow", width=22)
        table.add_column("Location", style="cyan", width=22)
        table.add_column("Problem & Recommended Fix", ratio=1)

        for idx, item in enumerate(report.warnings, 1):
            f = item.finding
            loc = f"{f.file_path}:{f.line_start}" if f.file_path else "—"
            details = [
                f"[bold]Problem:[/bold] {item.plain_english_explanation}",
            ]
            if f.code_snippet:
                details.append(
                    f"[bold yellow]⚠️ Flagged Code:[/bold yellow]\n[yellow]   {f.code_snippet}[/yellow]"
                )

            if item.exploitability_reasoning:
                details.append(
                    f"[bold yellow]🛡️ Risk Analysis & Impact:[/bold yellow] {item.exploitability_reasoning}"
                )

            details.append(f"[bold green]💡 How to fix:[/bold green] {item.fix_recommendation}")

            if item.suggested_replacement_code:
                details.append(
                    f"[bold green]🟢 Replacement Code:[/bold green]\n[green]   {item.suggested_replacement_code}[/green]"
                )

            table.add_row(
                str(idx),
                f"{f.title}\n[dim]{f.tool}[/dim]",
                loc,
                "\n".join(details),
            )

        console.print(table)

    # 4. Transparent False Positives Section
    if report.likely_false_positives:
        console.print()
        table = Table(
            title=f"🔍 Likely False Positives ({len(report.likely_false_positives)} item{'s' if len(report.likely_false_positives) != 1 else ''} — kept visible for full transparency)",
            border_style="blue",
            show_lines=True,
            expand=True,
        )
        table.add_column("#", width=3, style="dim")
        table.add_column("Flagged Item", style="dim", width=22)
        table.add_column("Location", style="cyan", width=22)
        table.add_column("Why the AI believes this is safe", ratio=1)

        for idx, item in enumerate(report.likely_false_positives, 1):
            f = item.finding
            loc = f"{f.file_path}:{f.line_start}" if f.file_path else "—"
            table.add_row(
                str(idx),
                f.title,
                loc,
                f"[italic]{item.exploitability_reasoning}[/italic]",
            )

        console.print(table)

    # 5. Telemetry & Cost Footer
    telemetry_parts = [f"Scanned in {report.scan_duration_seconds:.2f}s"]
    usage = report.token_usage
    if usage.total_tokens > 0:
        telemetry_parts.append(
            f"Tokens: {usage.prompt_tokens} prompt + {usage.completion_tokens} completion = {usage.total_tokens} total"
        )
        telemetry_parts.append(f"Est. Cost: ${usage.estimated_cost_usd:.4f}")

    console.print()
    console.print(f"[dim]{'  |  '.join(telemetry_parts)}[/dim]")
    console.print()


def print_network_report(report: Any) -> None:
    """Render a comprehensive network, IP intelligence, and security headers terminal report."""
    console.print()

    if hasattr(report, "discovered_endpoints"):
        print_project_network_report(report)
        return

    if report.error_message:
        console.print(
            Panel(
                f"[bold red]Network Audit Failed[/bold red]\n\n{report.error_message}",
                title="CRY Network & IP Intelligence",
                border_style="red",
            )
        )
        return

    # 1. Headline Score Banner
    grade = report.security_score
    grade_color = "green" if grade in ("A+", "A") else ("yellow" if grade in ("B", "C") else "red")
    badge = f"[bold white on {grade_color}]  GRADE: {grade}  [/bold white on {grade_color}]"

    banner_text = [
        f"{badge}  [bold {grade_color}]NETWORK DEFENSE SCORECARD[/bold {grade_color}]\n",
        f"[bold]Target:[/bold] [cyan]{report.target}[/cyan] (Resolved Host: {report.hostname})",
    ]
    if report.ssrf_risk_warning:
        banner_text.append(f"\n[bold red]🚨 ALERT: {report.ssrf_risk_warning}[/bold red]")

    console.print(
        Panel(
            "\n".join(banner_text),
            title="CRY Network & Host Intelligence",
            border_style=grade_color,
        )
    )

    # 2. IP & DNS Resolution Table
    ip_table = Table(
        title="🌐 IP Resolution & DNS Intelligence",
        border_style="cyan",
        show_lines=True,
        expand=True,
    )
    ip_table.add_column("Record Type", style="bold", width=20)
    ip_table.add_column("Resolved Value", style="cyan")
    ip_table.add_column("Security Context", style="dim")

    ipv4_str = ", ".join(report.ipv4_addresses) if report.ipv4_addresses else "None detected"
    ipv4_ctx = (
        "[red]Private RFC-1918 / Loopback[/red]"
        if report.is_private_ip
        else (
            "[red]Cloud IMDS Metadata[/red]"
            if report.is_metadata_ip
            else "[green]Public Routable Internet[/green]"
        )
    )
    ip_table.add_row("IPv4 (A)", ipv4_str, ipv4_ctx)

    ipv6_str = ", ".join(report.ipv6_addresses) if report.ipv6_addresses else "None detected"
    ip_table.add_row(
        "IPv6 (AAAA)",
        ipv6_str,
        "[dim]IPv6 Dual-Stack Support[/dim]"
        if report.ipv6_addresses
        else "[yellow]No IPv6 record[/yellow]",
    )

    ptr_str = report.reverse_dns or "No PTR record found"
    ip_table.add_row(
        "Reverse DNS (PTR)",
        ptr_str,
        "[green]Verified Canonical Host[/green]"
        if report.reverse_dns
        else "[dim]Unmapped PTR[/dim]",
    )

    console.print(ip_table)

    # 3. SSL/TLS Certificate Table
    if report.ssl_info:
        ssl_info = report.ssl_info
        ssl_color = (
            "red"
            if (ssl_info.is_expired or ssl_info.days_remaining < 7)
            else ("yellow" if ssl_info.days_remaining < 30 else "green")
        )
        ssl_status = (
            "[red]EXPIRED[/red]"
            if ssl_info.is_expired
            else f"[{ssl_color}]VALID ({ssl_info.days_remaining} days left)[/{ssl_color}]"
        )

        tls_table = Table(
            title="🔒 SSL/TLS Certificate & Transport Security",
            border_style=ssl_color,
            show_lines=True,
            expand=True,
        )
        tls_table.add_column("Property", style="bold", width=20)
        tls_table.add_column("Value", style="cyan")
        tls_table.add_column("Status / Risk", style="dim")

        tls_table.add_row("Certificate Status", ssl_status, f"Expires: {ssl_info.valid_to}")
        tls_table.add_row("Issuer Authority", ssl_info.issuer, "Trusted CA Hierarchy")
        tls_table.add_row("Subject CN", ssl_info.subject, "Domain Name Match")
        tls_table.add_row(
            "TLS Protocol",
            ssl_info.tls_version,
            "[green]Modern Transport Protocol[/green]"
            if "1.3" in ssl_info.tls_version or "1.2" in ssl_info.tls_version
            else "[red]Deprecated Protocol[/red]",
        )
        tls_table.add_row("Cipher Suite", ssl_info.cipher_suite, "Negotiated Cipher Suite")

        console.print(tls_table)

    # 4. HTTP Security Headers Table
    if report.security_headers:
        hdr_table = Table(
            title="🛡️ HTTP Defense-in-Depth Security Headers",
            border_style="blue",
            show_lines=True,
            expand=True,
        )
        hdr_table.add_column("Security Header", style="bold", width=26)
        hdr_table.add_column("Status", width=14)
        hdr_table.add_column("Current Value or Recommended Action", ratio=1)

        for h in report.security_headers:
            status_badge = "[green]✓ PRESENT[/green]" if h.present else "[red]✗ MISSING[/red]"
            val_or_rec = (
                f"[green]{h.value}[/green]" if h.present else f"[yellow]{h.recommendation}[/yellow]"
            )
            hdr_table.add_row(h.name, status_badge, val_or_rec)

        console.print(hdr_table)

    console.print()


def print_project_network_report(report: Any) -> None:
    """Render comprehensive project-wide network footprint and IP discovery report."""
    console.print()
    alert_color = "red" if report.ssrf_risks_count > 0 else "green"
    badge = (
        "[bold white on red]  SSRF ALERT  [/bold white on red]"
        if report.ssrf_risks_count > 0
        else "[bold white on green]  NETWORK POSTURE OK  [/bold white on green]"
    )

    banner_text = [
        f"{badge}  [bold {alert_color}]PROJECT NETWORK & IP FOOTPRINT AUDIT[/bold {alert_color}]\n",
        f"[bold]Project Target:[/bold] [cyan]{report.project_dir}[/cyan]",
        f"[bold]Local Host Environment:[/bold] {report.local_hostname} ([cyan]{report.local_outbound_ip}[/cyan])",
        f"[bold]Endpoints Discovered:[/bold] {report.total_endpoints_found} declared targets | [bold yellow]{report.private_ips_count} internal/private[/bold yellow] | [bold red]{report.ssrf_risks_count} SSRF risks[/bold red]",
    ]

    console.print(
        Panel(
            "\n".join(banner_text),
            title="CRY Project Network Intelligence",
            border_style=alert_color,
        )
    )

    if report.discovered_endpoints:
        table = Table(
            title="🌐 Discovered Network Endpoints & Live IP Resolutions",
            border_style="cyan",
            show_lines=True,
            expand=True,
        )
        table.add_column("Endpoint / Reference", style="bold cyan", width=30)
        table.add_column("Resolved IPv4 (A)", width=18)
        table.add_column("Security Context", width=22)
        table.add_column("Source Location", width=26, style="dim")
        table.add_column("SSRF / Risk Warning", ratio=1)

        for ep in report.discovered_endpoints:
            ips_str = ", ".join(ep.resolved_ips) if ep.resolved_ips else "Unresolved"
            ctx = (
                "[red bold]Cloud Metadata (IMDS)[/red bold]"
                if ep.is_metadata
                else (
                    "[yellow]Private / RFC-1918[/yellow]"
                    if ep.is_private
                    else "[green]Public Routable[/green]"
                )
            )
            warn = (
                f"[bold red]🚨 {ep.ssrf_warning}[/bold red]"
                if ep.ssrf_warning
                else (
                    "[green]✓ No immediate SSRF risk[/green]"
                    if not ep.is_private
                    else "[dim]Internal service[/dim]"
                )
            )
            loc = f"{ep.source_file}:{ep.line_number}"
            table.add_row(ep.raw_reference[:35], ips_str, ctx, loc, warn)

        console.print(table)
    else:
        console.print(
            "[dim]No hardcoded network endpoints or external IP addresses found in project files.[/dim]"
        )

    console.print()


def print_benchmark_scorecard(card: Any) -> None:
    """Render an individual AI model benchmark scorecard."""
    console.print()
    table = Table(
        title=f"📊 CRY Model Benchmark Scorecard: {card.model_name}",
        border_style="cyan",
        expand=True,
    )
    table.add_column("Evaluation Metric", style="bold", width=30)
    table.add_column("Score / Count", style="bold", width=20)
    table.add_column("Target Expectation", style="dim")

    table.add_row("Model Name", f"[cyan]{card.model_name}[/cyan]", "Tested Architecture")
    table.add_row("Provider Endpoint", card.provider_endpoint, "Inference Gateway")
    table.add_row("Total Ground-Truth Cases", str(card.total_cases), "-")
    table.add_row(
        "True Positives (Caught Bugs)",
        f"[green]{card.true_positives}[/green]",
        "Higher is better",
    )
    table.add_row(
        "True Negatives (Safe Code Passed)",
        f"[green]{card.true_negatives}[/green]",
        "Higher is better",
    )
    table.add_row(
        "False Positives (Noisy Alarms)",
        f"[yellow]{card.false_positives}[/yellow]",
        "Aim for 0",
    )

    fn_style = "[bold red]" if card.false_negatives > 0 else "[green]"
    table.add_row(
        "False Negatives (Missed Vulnerabilities)",
        f"{fn_style}{card.false_negatives}[/]",
        "[bold red]MUST BE 0[/bold red]",
    )

    table.add_row("Precision", f"{card.precision:.2%}", "Higher is better (> 85%)")
    table.add_row("Recall (Sensitivity)", f"{card.recall:.2%}", "Must be > 95%")
    table.add_row("F1 Score", f"{card.f1_score:.2%}", "Must be > 90%")
    table.add_row("Inference Latency", f"{card.latency_seconds:.2f}s", "Fast triage turnaround")
    if hasattr(card, "actionable_patch_rate") and card.actionable_patch_rate > 0:
        table.add_row(
            "Actionable Patch Rate",
            f"{card.actionable_patch_rate:.1%}",
            "Valid replacement code provided",
        )
    table.add_row(
        "Token Usage & Cost",
        f"{card.token_usage.total_tokens} tokens (${card.token_usage.estimated_cost_usd:.4f})",
        "Cost efficiency",
    )

    console.print(table)
    console.print()


def print_model_comparison_table(leaderboard: Any) -> None:
    """Render side-by-side comparative leaderboard for multiple evaluated models."""
    console.print()
    table = Table(
        title="🏆 AI Security Model Leaderboard & Comparison",
        border_style="magenta",
        expand=True,
    )
    table.add_column("Model Identifier", style="bold cyan")
    table.add_column("Precision", justify="center")
    table.add_column("Recall", justify="center")
    table.add_column("F1 Score", justify="center")
    table.add_column("False Negatives", justify="center")
    table.add_column("Latency", justify="center")
    table.add_column("Est. Cost", justify="center")

    for card in leaderboard.scorecards:
        fn_text = (
            f"[bold red]{card.false_negatives}[/bold red]"
            if card.false_negatives > 0
            else "[bold green]0[/bold green]"
        )
        f1_color = "green" if card.f1_score >= 0.9 else "yellow"
        table.add_row(
            card.model_name,
            f"{card.precision:.1%}",
            f"{card.recall:.1%}",
            f"[{f1_color}]{card.f1_score:.1%}[/{f1_color}]",
            fn_text,
            f"{card.latency_seconds:.2f}s",
            f"${card.token_usage.estimated_cost_usd:.4f}",
        )

    console.print(table)

    if hasattr(leaderboard, "get_recommendation"):
        rec = leaderboard.get_recommendation()
        if rec:
            reasons_text = "\n".join(f"  • {r}" for r in rec["reasons"])
            rec_content = (
                f"[bold green]⭐ Recommended Model:[/bold green] [bold cyan]{rec['winner_model']}[/bold cyan]\n"
                f"[dim]Why:[/dim]\n{reasons_text}\n\n"
                f"[dim]Quick Setup:[/dim] Run [bold]cry configure[/bold] or set [cyan]LLM_MODEL={rec['winner_model']}[/cyan] in your .env"
            )
            console.print(
                Panel(
                    rec_content,
                    title="🎯 Optimal Model Recommendation",
                    border_style="green",
                    expand=True,
                )
            )

    console.print()
