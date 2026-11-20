"""Real-application benchmark runner for CRY.

Clones target open-source applications pinned to immutable commit hashes,
runs CRY's offline scanner suite against them, validates findings against
ground-truth manifest expectations, and outputs diffs.
"""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cry.exclusions import ExclusionStats
from cry.scanners.network import scan_network_code_patterns
from cry.scanners.sast import scan_directory as scan_sast
from cry.scanners.secrets import scan_directory as scan_secrets
from cry.triage.engine import TriageEngine

console = Console()
MANIFEST_PATH = Path(__file__).resolve().parent / "manifest.json"


def load_real_apps_manifest(path: Path | None = None) -> dict[str, Any]:
    """Load the ground-truth real-apps manifest."""
    m_path = path or MANIFEST_PATH
    if not m_path.is_file():
        raise FileNotFoundError(f"Real-apps benchmark manifest not found at: {m_path}")
    with open(m_path, encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)
    return data


def resolve_target_dir(
    target_config: dict[str, Any],
    cache_dir: Path | None = None,
) -> Path:
    """Locate local cache of the target repository or clone and checkout pinned commit.

    Exits non-zero if git or clone fails.
    """
    repo_name: str = (
        str(target_config.get("name", "app")).lower().replace(" ", "_").replace("owasp_", "")
    )
    pinned_commit: str = str(target_config.get("pinned_commit", ""))
    repo_url: str = str(target_config.get("repo_url", ""))

    # Candidate locations to find existing local clone
    candidates: list[Path] = []
    if cache_dir:
        candidates.append(cache_dir / repo_name)
    candidates.append(Path(tempfile.gettempdir()) / repo_name)
    candidates.append(Path.cwd() / ".cache" / repo_name)
    candidates.append(Path(__file__).resolve().parent / "cache" / repo_name)

    for cand in candidates:
        cand_path: Path = Path(cand)
        if cand_path.is_dir() and (cand_path / ".git").is_dir():
            # Check if this repository is already at the target commit or has the files
            try:
                res = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=cand_path,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                head_commit = res.stdout.strip()
                if head_commit.startswith(pinned_commit[:7]) or pinned_commit.startswith(
                    head_commit[:7]
                ):
                    return Path(cand_path)
                # If valid git repo, try checking out pinned commit
                co = subprocess.run(
                    ["git", "checkout", pinned_commit],
                    cwd=cand_path,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if co.returncode == 0:
                    return Path(cand_path)
            except Exception:
                pass

    # Destination directory to clone into
    dest_dir: Path = (
        (cache_dir / repo_name) if cache_dir else (Path(tempfile.gettempdir()) / repo_name)
    )

    if dest_dir.exists():
        shutil.rmtree(dest_dir, ignore_errors=True)

    dest_dir.parent.mkdir(parents=True, exist_ok=True)

    console.print(
        f"[bold cyan]Cloning {target_config['name']} from {repo_url} (pinned: {pinned_commit[:8]})...[/bold cyan]"
    )

    # 1. Clone repository
    clone_res = subprocess.run(
        ["git", "clone", repo_url, str(dest_dir)],
        capture_output=True,
        text=True,
        check=False,
    )
    if clone_res.returncode != 0:
        err_msg = clone_res.stderr.strip() or clone_res.stdout.strip()
        console.print(
            Panel(
                f"[bold red]Git clone failed for {repo_url}:[/bold red]\n{err_msg}",
                border_style="red",
            )
        )
        raise RuntimeError(f"Failed to clone {repo_url}: {err_msg}")

    # 2. Checkout pinned commit
    co_res = subprocess.run(
        ["git", "checkout", pinned_commit],
        cwd=dest_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    if co_res.returncode != 0:
        err_msg = co_res.stderr.strip() or co_res.stdout.strip()
        console.print(
            Panel(
                f"[bold red]Failed to checkout pinned commit {pinned_commit}:[/bold red]\n{err_msg}",
                border_style="red",
            )
        )
        raise RuntimeError(f"Failed to checkout commit {pinned_commit}: {err_msg}")

    final_dest_dir: Path = Path(dest_dir)
    return final_dest_dir


def evaluate_real_app(
    target_config: dict[str, Any],
    target_dir: Path,
) -> dict[str, Any]:
    """Execute offline scan on target and compare against manifest expectations."""
    exclusion_stats = ExclusionStats()

    # 1. Run offline scanners
    secrets = scan_secrets(target_dir, stats=exclusion_stats, include_tests_and_docs=False)
    sast = scan_sast(target_dir, stats=exclusion_stats, include_tests_and_docs=False)
    net = scan_network_code_patterns(
        target_dir, stats=exclusion_stats, include_tests_and_docs=False
    )
    raw_findings = secrets + sast + net

    # 2. Run offline heuristic triage
    triage = TriageEngine()
    report = triage._heuristic_fallback(raw_findings, target_dir, include_tests_and_docs=False)

    actual_blockers = report.blockers
    actual_warnings = report.warnings

    def norm_path(p: str | None) -> str:
        return (p or "").replace("\\", "/").strip("/")

    # Group findings by normalized relative file path
    actual_blocker_map: dict[str, list[Any]] = {}
    for b in actual_blockers:
        np = norm_path(b.finding.file_path)
        actual_blocker_map.setdefault(np, []).append(b.finding)

    actual_warning_map: dict[str, list[Any]] = {}
    for w in actual_warnings:
        np = norm_path(w.finding.file_path)
        actual_warning_map.setdefault(np, []).append(w.finding)

    diffs: list[str] = []

    # A. Check expected blocker files
    for exp_bf in target_config.get("expected_blocker_files", []):
        norm_exp = norm_path(exp_bf)
        matched = any(norm_exp in path for path in actual_blocker_map)
        if not matched:
            diffs.append(
                f"MISSING BLOCKER FILE: Expected blocker in '{exp_bf}', but none was found."
            )

    # B. Check expected warning files
    for exp_wf in target_config.get("expected_warning_files", []):
        norm_exp = norm_path(exp_wf)
        matched = any(norm_exp in path for path in actual_warning_map)
        if not matched:
            diffs.append(
                f"MISSING WARNING FILE: Expected warning in '{exp_wf}', but none was found."
            )

    # C. Check expected clean files
    for clean_f in target_config.get("expected_clean_files", []):
        norm_clean = norm_path(clean_f)
        b_hits = [p for p in actual_blocker_map if norm_clean in p]
        w_hits = [p for p in actual_warning_map if norm_clean in p]
        if b_hits:
            diffs.append(
                f"UNEXPECTED BLOCKER IN CLEAN FILE: Clean file '{clean_f}' produced blockers: {b_hits}."
            )
        if w_hits:
            diffs.append(
                f"UNEXPECTED WARNING IN CLEAN FILE: Clean file '{clean_f}' produced warnings: {w_hits}."
            )

    # D. Check expected totals
    expected_totals = target_config.get("expected_totals", {})
    if "blockers" in expected_totals and len(actual_blockers) != expected_totals["blockers"]:
        diffs.append(
            f"TOTAL BLOCKERS MISMATCH: Expected {expected_totals['blockers']}, got {len(actual_blockers)}."
        )

    if "warnings" in expected_totals and len(actual_warnings) != expected_totals["warnings"]:
        diffs.append(
            f"TOTAL WARNINGS MISMATCH: Expected {expected_totals['warnings']}, got {len(actual_warnings)}."
        )

    # E. Check detailed finding expectations
    for check in target_config.get("finding_checks", []):
        c_path = norm_path(check["file_path"])
        status = check.get("status")
        cwe = check.get("cwe_id")
        min_count = check.get("min_count", 1)

        if status == "BLOCKER":
            matching = [
                f
                for path, flist in actual_blocker_map.items()
                if c_path in path
                for f in flist
                if not cwe or f.cwe_id == cwe
            ]
            if len(matching) < min_count:
                diffs.append(
                    f"DETAILED CHECK FAILED: '{check['file_path']}' expected >= {min_count} {cwe or ''} blockers, got {len(matching)}."
                )
        elif status == "WARNING":
            matching = [
                f
                for path, flist in actual_warning_map.items()
                if c_path in path
                for f in flist
                if not cwe or f.cwe_id == cwe
            ]
            if len(matching) < min_count:
                diffs.append(
                    f"DETAILED CHECK FAILED: '{check['file_path']}' expected >= {min_count} {cwe or ''} warnings, got {len(matching)}."
                )
        elif status == "CLEAN":
            b_hits = [
                f for path, flist in actual_blocker_map.items() if c_path in path for f in flist
            ]
            w_hits = [
                f for path, flist in actual_warning_map.items() if c_path in path for f in flist
            ]
            if b_hits or w_hits:
                diffs.append(
                    f"CLEAN FILE FAILED: '{check['file_path']}' expected 0 findings, got {len(b_hits)} blockers and {len(w_hits)} warnings."
                )

    return {
        "name": target_config["name"],
        "pinned_commit": target_config["pinned_commit"],
        "passed": len(diffs) == 0,
        "diffs": diffs,
        "actual_totals": {
            "blockers": len(actual_blockers),
            "warnings": len(actual_warnings),
        },
        "expected_totals": expected_totals,
        "blockers": [
            {
                "file": norm_path(b.finding.file_path),
                "line": b.finding.line_start,
                "title": b.finding.title,
                "cwe": b.finding.cwe_id,
            }
            for b in actual_blockers
        ],
        "warnings": [
            {
                "file": norm_path(w.finding.file_path),
                "line": w.finding.line_start,
                "title": w.finding.title,
                "cwe": w.finding.cwe_id,
            }
            for w in actual_warnings
        ],
        "exclusions": exclusion_stats.format_summary(),
    }


def run_real_apps_benchmark(
    manifest_path: Path | None = None,
    cache_dir: Path | None = None,
) -> int:
    """Run real-apps benchmark and return non-zero exit code if any expectation fails."""
    manifest = load_real_apps_manifest(manifest_path)
    targets = manifest.get("targets", [])

    console.print(
        Panel.fit(
            f"[bold cyan]CRY Real-Application Benchmark Harness v{manifest.get('version', '0.4.1')}[/bold cyan]\n"
            f"[dim]Targets: {len(targets)} real-world open-source application(s)[/dim]",
            border_style="cyan",
        )
    )

    all_passed = True
    results_summary: list[dict[str, Any]] = []

    for target in targets:
        target_name = target["name"]
        console.print(f"\n[bold]Evaluating: [cyan]{target_name}[/cyan][/bold]...")

        try:
            target_dir = resolve_target_dir(target, cache_dir)
        except Exception as e:
            console.print(
                f"[bold red]FATAL: Could not resolve target {target_name}: {e}[/bold red]"
            )
            return 1

        eval_result = evaluate_real_app(target, target_dir)
        results_summary.append(eval_result)

        table = Table(title=f"Benchmark Evaluation: {target_name}", border_style="cyan")
        table.add_column("Category", style="bold")
        table.add_column("Actual", style="green")
        table.add_column("Expected", style="dim")
        table.add_column("Status", style="bold")

        act_b = eval_result["actual_totals"]["blockers"]
        exp_b = eval_result["expected_totals"].get("blockers", "-")
        b_status = "[green]MATCH[/green]" if act_b == exp_b else "[red]DIFF[/red]"
        table.add_row("Blockers", str(act_b), str(exp_b), b_status)

        act_w = eval_result["actual_totals"]["warnings"]
        exp_w = eval_result["expected_totals"].get("warnings", "-")
        w_status = "[green]MATCH[/green]" if act_w == exp_w else "[red]DIFF[/red]"
        table.add_row("Warnings", str(act_w), str(exp_w), w_status)

        console.print(table)

        if not eval_result["passed"]:
            all_passed = False
            console.print("\n[bold red]Diffs Detected against Manifest:[/bold red]")
            for d in eval_result["diffs"]:
                console.print(f"  [red]• {d}[/red]")
        else:
            console.print(
                f"[bold green]✔ All expectations passed for {target_name} ({act_b} blockers, {act_w} warnings)![/bold green]"
            )

    # Save results to evals/results/real_apps_nodegoat.json
    results_dir = Path(__file__).resolve().parent.parent / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    out_file = results_dir / "real_apps_nodegoat.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(
            {
                "suite": "real_apps_benchmark",
                "version": manifest.get("version", "0.4.1"),
                "results": results_summary,
            },
            f,
            indent=2,
        )
    console.print(f"\n[dim]Benchmark results recorded to: [cyan]{out_file}[/cyan][/dim]")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(run_real_apps_benchmark())
