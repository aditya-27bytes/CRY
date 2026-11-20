"""Declarative security rules catalog listing and validation."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from cry.rules.manager import RuleManager


def run_list_rules(category: str | None, console: Console) -> None:
    """List all loaded security rules from catalog and workspace configuration."""
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


def run_test_rules(console: Console) -> None:
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
