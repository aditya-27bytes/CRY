"""Unit tests for AST Taint Analysis (Phase 3) and BYOM Model Evaluation (Phase 1)."""

import tempfile
from pathlib import Path

from cry.evals.benchmark import run_model_benchmark
from cry.scanners.taint import analyze_taint_in_javascript, analyze_taint_in_python
from cry.triage.context_graph import build_context_graph


def test_python_ast_taint_detection() -> None:
    """Python AST correctly tracks taint from request.args through variable assignment to sink."""
    with tempfile.TemporaryDirectory() as td:
        py_file = Path(td) / "app.py"
        py_file.write_text(
            """
import os

def handle_request():
    user_id = request.args.get("id")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
""",
            encoding="utf-8",
        )

        # Line 7 is cursor.execute(query)
        res = analyze_taint_in_python(py_file, 7)
        assert res is not None
        assert res.is_tainted is True
        assert res.confidence >= 0.90
        assert "cursor.execute" in (res.sink or "")


def test_python_ast_constant_literal_detected() -> None:
    """Python AST detects when a sink call uses only constant literals with no variables."""
    with tempfile.TemporaryDirectory() as td:
        py_file = Path(td) / "safe_app.py"
        py_file.write_text(
            """
def healthcheck():
    cursor.execute("SELECT 1")
""",
            encoding="utf-8",
        )

        res = analyze_taint_in_python(py_file, 3)
        assert res is not None
        assert res.is_tainted is False
        assert res.is_literal_constant is True
        assert res.confidence <= 0.30


def test_javascript_taint_detection() -> None:
    """JavaScript structural dataflow traces req.query to redirect sink."""
    code = """
export function redirectHandler(req, res) {
    const targetUrl = req.query.url ?? "/";
    res.redirect(targetUrl);
}
"""
    res = analyze_taint_in_javascript(code, 4)
    assert res is not None
    assert res.is_tainted is True
    assert res.confidence >= 0.90
    assert "req.query" in (res.source or "")


def test_context_graph_enrichment() -> None:
    """ContextGraph extracts function signature and dataflow summary."""
    with tempfile.TemporaryDirectory() as td:
        py_file = Path(td) / "endpoint.py"
        py_file.write_text(
            """
import html

def login_user(req):
    user = req.args.get('user')
    os.system(user)
""",
            encoding="utf-8",
        )

        cg = build_context_graph(Path(td), "endpoint.py", 6)
        prompt_text = cg.format_for_llm_prompt()
        assert "login_user" in prompt_text
        assert "CONFIRMED TAINT" in prompt_text or "req.args" in prompt_text


def test_byom_model_benchmark_offline() -> None:
    """BYOM benchmark executes deterministically with 100% precision and recall."""
    card = run_model_benchmark(no_ai=True)
    assert card.total_cases >= 10
    assert card.false_negatives == 0
    assert card.precision == 1.0
    assert card.recall == 1.0
    assert card.f1_score == 1.0
    assert card.actionable_patch_rate == 1.0


def test_model_comparison_leaderboard_recommendation() -> None:
    """Leaderboard mathematically determines the optimal model recommendation."""
    from cry.models import ModelBenchmarkScorecard, ModelComparisonLeaderboard, TokenUsage

    leaderboard = ModelComparisonLeaderboard()

    # Model A: 100% recall, 4.96s latency, $0.0027
    card_a = ModelBenchmarkScorecard(
        model_name="openai/gpt-oss-120b",
        provider_endpoint="https://api.openai.com",
        total_cases=13,
        true_positives=7,
        true_negatives=6,
        false_positives=0,
        false_negatives=0,
        latency_seconds=4.96,
        token_usage=TokenUsage(total_tokens=1500, estimated_cost_usd=0.0027),
    )
    card_a.compute_metrics()

    # Model B: 100% recall, 3.88s latency, $0.0024 (faster & cheaper)
    card_b = ModelBenchmarkScorecard(
        model_name="llama-3.3-70b-versatile",
        provider_endpoint="https://api.groq.com",
        total_cases=13,
        true_positives=7,
        true_negatives=6,
        false_positives=0,
        false_negatives=0,
        latency_seconds=3.88,
        token_usage=TokenUsage(total_tokens=1500, estimated_cost_usd=0.0024),
    )
    card_b.compute_metrics()

    leaderboard.scorecards.extend([card_a, card_b])
    rec = leaderboard.get_recommendation()

    assert rec is not None
    assert rec["winner_model"] == "llama-3.3-70b-versatile"
    assert rec["fastest_model"] == "llama-3.3-70b-versatile"
    assert rec["cheapest_model"] == "llama-3.3-70b-versatile"
    assert any("Zero False Negatives" in r for r in rec["reasons"])
