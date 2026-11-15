"""BYOM (Bring Your Own Model) evaluation and comparative benchmarking harness."""

import asyncio
import json
import time
from pathlib import Path

from cry.config import settings
from cry.models import (
    ModelBenchmarkScorecard,
    ModelComparisonLeaderboard,
    TokenUsage,
    VerdictReport,
)
from cry.scanners.network import scan_network_code_patterns
from cry.scanners.sast import scan_directory as scan_sast
from cry.scanners.secrets import scan_directory as scan_secrets
from cry.triage.client import LLMClient
from cry.triage.engine import TriageEngine
from evals.schema import BenchmarkCase

DEFAULT_DATASET = Path(__file__).resolve().parent.parent.parent / "evals" / "datasets" / "ground_truth.json"
DEFAULT_SAMPLES = Path(__file__).resolve().parent.parent.parent / "evals" / "datasets" / "samples"


def load_ground_truth(dataset_path: Path | None = None) -> list[BenchmarkCase]:
    """Load benchmark ground-truth test cases."""
    target_path = dataset_path or DEFAULT_DATASET
    if not target_path.is_file():
        # Fallback search
        alt = Path.cwd() / "evals" / "datasets" / "ground_truth.json"
        if alt.is_file():
            target_path = alt
        else:
            return []

    with open(target_path, encoding="utf-8") as f:
        raw_data = json.load(f)
    return [BenchmarkCase(**item) for item in raw_data]


def run_model_benchmark(
    model: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    no_ai: bool = False,
    dataset_path: Path | None = None,
    samples_dir: Path | None = None,
) -> ModelBenchmarkScorecard:
    """Evaluate a specific AI model or offline baseline against the ground-truth benchmark suite."""
    effective_model = model or (settings.LLM_MODEL if not no_ai else "Offline Heuristic (No AI)")
    effective_base_url = base_url or (settings.LLM_BASE_URL if not no_ai else "local")
    effective_api_key = api_key if api_key is not None else settings.LLM_API_KEY

    samples = samples_dir or DEFAULT_SAMPLES
    if not samples.is_dir():
        alt = Path.cwd() / "evals" / "datasets" / "samples"
        if alt.is_dir():
            samples = alt

    cases = load_ground_truth(dataset_path)

    # 1. Run live scanners on benchmark sample files across SAST, Secrets, and Network
    raw_findings = (
        scan_secrets(samples)
        + scan_sast(samples)
        + scan_network_code_patterns(samples)
    )

    # 2. Run Triage
    start_time = time.time()
    token_usage = TokenUsage()

    if no_ai:
        triage = TriageEngine()
        report: VerdictReport = triage._heuristic_fallback(raw_findings, samples)
    else:
        client = LLMClient(
            base_url=effective_base_url,
            api_key=effective_api_key,
            model=effective_model,
        )
        triage = TriageEngine(client=client)
        try:
            report = asyncio.run(triage.triage_findings(raw_findings, samples))
            token_usage = report.token_usage
        except Exception:
            report = triage._heuristic_fallback(raw_findings, samples)

    latency = round(time.time() - start_time, 2)

    # 3. Score against ground truth
    active_threat_files = {
        item.finding.file_path
        for item in (report.blockers + report.warnings)
        if item.finding.file_path
    }

    scorecard = ModelBenchmarkScorecard(
        model_name=effective_model,
        provider_endpoint=effective_base_url,
        total_cases=len(cases),
        latency_seconds=latency,
        token_usage=token_usage,
    )

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

    # 4. Measure actionable patch quality rate
    confirmed_threats = report.blockers + report.warnings
    threats_with_patches = sum(
        1
        for t in confirmed_threats
        if (t.suggested_replacement_code and len(t.suggested_replacement_code.strip()) > 0)
        or (t.fix_recommendation and len(t.fix_recommendation.strip()) > 0)
    )
    scorecard.actionable_patch_rate = (
        (threats_with_patches / len(confirmed_threats)) if confirmed_threats else 1.0
    )

    scorecard.compute_metrics()
    return scorecard


def run_multi_model_benchmark(
    models: list[str],
    base_url: str | None = None,
    api_key: str | None = None,
) -> ModelComparisonLeaderboard:
    """Benchmark multiple AI models consecutively and return a comparative leaderboard."""
    leaderboard = ModelComparisonLeaderboard()
    for m in models:
        card = run_model_benchmark(model=m.strip(), base_url=base_url, api_key=api_key)
        leaderboard.scorecards.append(card)
    return leaderboard


def export_benchmark_markdown(
    scorecard_or_leaderboard: ModelBenchmarkScorecard | ModelComparisonLeaderboard,
    output_path: Path,
) -> None:
    """Export benchmark results as a clean Markdown report."""
    lines: list[str] = [
        "# CRY AI Security Model Benchmark Report",
        "",
        "> Ground-truth evaluation testing accuracy, precision, recall, and token costs.",
        "",
    ]

    cards = (
        scorecard_or_leaderboard.scorecards
        if isinstance(scorecard_or_leaderboard, ModelComparisonLeaderboard)
        else [scorecard_or_leaderboard]
    )

    lines.append("| Model | Precision | Recall (Sensitivity) | F1 Score | False Negatives | Latency | Total Cost ($) |")
    lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |")

    for c in cards:
        lines.append(
            f"| **`{c.model_name}`** | `{c.precision:.2%}` | `{c.recall:.2%}` | `{c.f1_score:.2%}` | **`{c.false_negatives}`** | `{c.latency_seconds}s` | `${c.token_usage.estimated_cost_usd:.4f}` |"
        )

    if isinstance(scorecard_or_leaderboard, ModelComparisonLeaderboard):
        rec = scorecard_or_leaderboard.get_recommendation()
        if rec:
            lines.append("")
            lines.append("## 🏆 Optimal Model Recommendation")
            lines.append(f"- **Recommended Model**: `{rec['winner_model']}`")
            lines.append(f"- **Fastest Model**: `{rec['fastest_model']}`")
            lines.append(f"- **Lowest Cost**: `{rec['cheapest_model']}`")
            lines.append("- **Evaluation Factors**:")
            for reason in rec["reasons"]:
                lines.append(f"  - {reason}")

    lines.append("")
    lines.append("### Metric Definitions:")
    lines.append("- **Recall (Sensitivity)**: Percentage of real vulnerabilities successfully detected. (Target: > 95%)")
    lines.append("- **False Negatives**: Real vulnerabilities that were completely missed. (**Must be 0**)")
    lines.append("- **Precision**: Percentage of flagged issues that are genuinely dangerous. (Target: > 85%)")
    lines.append("- **F1 Score**: Harmonic mean balancing precision and recall.")

    output_path.write_text("\n".join(lines), encoding="utf-8")
