"""Evaluation runner to benchmark CRY's triage accuracy against ground truth datasets."""

import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cry.models import VerdictReport
from evals.schema import BenchmarkCase, BenchmarkScorecard

console = Console()


def load_ground_truth(dataset_path: Path) -> list[BenchmarkCase]:
    """Load benchmark ground-truth test cases."""
    with open(dataset_path, encoding="utf-8") as f:
        raw_data = json.load(f)
    return [BenchmarkCase(**item) for item in raw_data]


def score_triage_run(cases: list[BenchmarkCase], report: VerdictReport) -> BenchmarkScorecard:
    """Compare a VerdictReport against ground truth cases.

    Rules:
    - If a case is a real vulnerability and is flagged as a BLOCKER or WARNING -> True Positive (TP)
    - If a case is a real vulnerability but is marked LIKELY_FALSE_POSITIVE or missed entirely -> False Negative (FN) [CRITICAL FAILURE]
    - If a case is safe/trap and is marked as LIKELY_FALSE_POSITIVE or clean -> True Negative (TN)
    - If a case is safe/trap but is wrongly labeled an active BLOCKER -> False Positive (FP)
    """
    scorecard = BenchmarkScorecard(total_cases=len(cases))

    # Index triaged findings by file path
    active_threat_files = {
        item.finding.file_path
        for item in (report.blockers + report.warnings)
        if item.finding.file_path
    }

    for case in cases:
        case_filename = Path(case.file_path).name
        detected_as_active = any(
            case_filename == Path(threat_file or "").name for threat_file in active_threat_files
        )

        if case.is_vulnerability:
            if detected_as_active:
                scorecard.true_positives += 1
            else:
                scorecard.false_negatives += 1
                scorecard.missed_case_ids.append(case.case_id)
        else:
            if detected_as_active:
                scorecard.false_positives += 1
                scorecard.wrongly_flagged_case_ids.append(case.case_id)
            else:
                scorecard.true_negatives += 1

    scorecard.compute_metrics()
    return scorecard


def print_scorecard(scorecard: BenchmarkScorecard) -> None:
    """Print a Rich formatted scorecard table."""
    table = Table(title="CRY Accuracy & Evaluation Scorecard", border_style="cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Score / Count", style="bold")
    table.add_column("Target Expectation", style="dim")

    table.add_row("Total Test Cases", str(scorecard.total_cases), "-")
    table.add_row(
        "True Positives (Bugs Caught)",
        f"[green]{scorecard.true_positives}[/green]",
        "Higher is better",
    )
    table.add_row(
        "True Negatives (Safe Code Passed)",
        f"[green]{scorecard.true_negatives}[/green]",
        "Higher is better",
    )
    table.add_row(
        "False Positives (Noisy Warnings)",
        f"[yellow]{scorecard.false_positives}[/yellow]",
        "Aim for 0",
    )

    fn_style = "[red bold]" if scorecard.false_negatives > 0 else "[green]"
    table.add_row(
        "False Negatives (Missed Vulnerabilities)",
        f"{fn_style}{scorecard.false_negatives}[/]",
        "[bold red]MUST BE 0[/bold red]",
    )

    table.add_row("Precision", f"{scorecard.precision:.2%}", "Higher is better")
    table.add_row("Recall (Sensitivity)", f"{scorecard.recall:.2%}", "Goal > 95%")
    table.add_row("F1 Score", f"{scorecard.f1_score:.2%}", "Goal > 90%")

    console.print(table)

    if scorecard.false_negatives > 0:
        console.print(
            Panel(
                f"[bold red]CRITICAL ALERT: {scorecard.false_negatives} real vulnerabilities were MISSED or WRONGLY DISMISSED![/bold red]\n"
                f"Missed Case IDs: {', '.join(scorecard.missed_case_ids)}\n"
                "Adjust prompt sensitivity before shipping.",
                border_style="red",
            )
        )


if __name__ == "__main__":
    import asyncio

    from cry.scanners.sast import scan_directory as scan_sast
    from cry.scanners.secrets import scan_directory as scan_secrets
    from cry.triage.engine import TriageEngine

    dataset_file = Path(__file__).parent / "datasets" / "ground_truth.json"
    samples_dir = Path(__file__).parent / "datasets" / "samples"

    if dataset_file.exists():
        benchmark_cases = load_ground_truth(dataset_file)
        console.print(
            f"[bold cyan]Running CRY accuracy evaluation against {len(benchmark_cases)} ground-truth cases...[/bold cyan]\n"
        )

        # 1. Run live scanners on benchmark sample files
        secrets = scan_secrets(samples_dir)
        sast = scan_sast(samples_dir)
        raw_findings = secrets + sast
        console.print(
            f"Scanners detected {len(raw_findings)} raw finding(s) across benchmark samples."
        )

        # 2. Run Triage Engine
        import sys

        triage = TriageEngine()
        if "--no-ai" in sys.argv or not triage.client.is_configured:
            console.print("[dim]Evaluating scanner baseline (heuristic mode)...[/dim]")
            report = triage._heuristic_fallback(raw_findings, samples_dir)
        else:
            try:
                report = asyncio.run(triage.triage_findings(raw_findings, samples_dir))
            except Exception as e:
                console.print(
                    f"[yellow]AI triage connection failed ({e}); falling back to heuristic...[/yellow]"
                )
                report = triage._heuristic_fallback(raw_findings, samples_dir)

        # 3. Score against ground truth
        scorecard = score_triage_run(benchmark_cases, report)
        print_scorecard(scorecard)

        # 4. Save results to JSON if requested
        output_path: Path | None = None
        for idx, arg in enumerate(sys.argv):
            if arg in ("--output", "-o") and idx + 1 < len(sys.argv):
                output_path = Path(sys.argv[idx + 1])
                break

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            from cry import __version__

            results_payload = {
                "version": __version__,
                "total_cases": scorecard.total_cases,
                "found": scorecard.true_positives,
                "missed": scorecard.false_negatives,
                "false_alarms": scorecard.false_positives,
                "true_negatives": scorecard.true_negatives,
                "precision": round(scorecard.precision, 4),
                "recall": round(scorecard.recall, 4),
                "f1_score": round(scorecard.f1_score, 4),
                "missed_case_ids": scorecard.missed_case_ids,
                "wrongly_flagged_case_ids": scorecard.wrongly_flagged_case_ids,
            }
            output_path.write_text(json.dumps(results_payload, indent=2), encoding="utf-8")
            console.print(
                f"[bold green]Evaluation results saved to: [cyan]{output_path}[/cyan][/bold green]"
            )
