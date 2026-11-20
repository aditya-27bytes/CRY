"""Model benchmark execution and evaluation reports."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from cry.config import settings
from cry.evals.benchmark import (
    export_benchmark_markdown,
    run_model_benchmark,
    run_multi_model_benchmark,
)
from cry.reporters.terminal import (
    print_benchmark_scorecard,
    print_model_comparison_table,
)


def run_eval(
    model: str | None,
    base_url: str | None,
    api_key: str | None,
    no_ai: bool,
    compare: str | None,
    markdown_output: Path | None,
    real_apps: bool,
    console: Console,
) -> int:
    """Benchmark an AI model or compare multiple models side-by-side on ground-truth security cases."""
    if real_apps:
        from evals.real_apps.runner import run_real_apps_benchmark

        return run_real_apps_benchmark()

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

    return 0
