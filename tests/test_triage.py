"""Tests for the triage engine and reporters."""

import json
from pathlib import Path

from cry.models import (
    Category,
    Finding,
    Severity,
    TriagedFinding,
    TriageStatus,
    Verdict,
    VerdictReport,
)
from cry.reporters.json_reporter import export_json_report
from cry.triage.client import LLMClient
from cry.triage.engine import TriageEngine, extract_code_context

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_extract_code_context() -> None:
    """Must correctly extract +/- lines around flagged line number."""
    ctx = extract_code_context(FIXTURES_DIR, "vulnerable_app.py", 10, context_lines=3)
    assert ctx is not None
    assert ">>>" in ctx  # The flagged line marker
    assert "10 |" in ctx


def test_extract_code_context_nonexistent_file() -> None:
    """Must return None cleanly for nonexistent files without throwing."""
    ctx = extract_code_context(FIXTURES_DIR, "nonexistent_file_12345.py", 5)
    assert ctx is None


def test_heuristic_fallback_triage() -> None:
    """Heuristic fallback should sort critical findings into blockers and medium into warnings."""
    engine = TriageEngine(client=LLMClient(api_key=""))
    findings = [
        Finding(
            id="f-1",
            tool="cry-secrets",
            title="Stripe Key",
            description="Leaked key",
            category=Category.SECRET_EXPOSURE,
            severity=Severity.CRITICAL,
        ),
        Finding(
            id="f-2",
            tool="cry-sast",
            title="CORS Wildcard",
            description="CORS allows *",
            category=Category.MISCONFIGURATION,
            severity=Severity.MEDIUM,
        ),
    ]

    report = engine._heuristic_fallback(findings, FIXTURES_DIR)
    assert report.verdict == Verdict.DONT_SHIP
    assert len(report.blockers) == 1
    assert report.blockers[0].status == TriageStatus.CONFIRMED_BLOCKER
    assert len(report.warnings) == 1
    assert report.warnings[0].status == TriageStatus.WARNING


def test_json_report_export(tmp_path: Path) -> None:
    """Must export a valid JSON file matching VerdictReport schema."""
    finding = Finding(
        id="f-export",
        tool="cry-test",
        title="Test Flaw",
        description="Just a test",
        category=Category.OTHER,
        severity=Severity.LOW,
    )
    triaged = TriagedFinding(
        finding=finding,
        status=TriageStatus.WARNING,
        exploitability_reasoning="Reasoning here",
        plain_english_explanation="Explanation here",
        fix_recommendation="Fix recommendation",
    )
    report = VerdictReport(
        verdict=Verdict.SHIP,
        summary="Safe test summary",
        target=".",
        blockers=[],
        warnings=[triaged],
    )

    out_file = tmp_path / "test_report.json"
    saved = export_json_report(report, out_file)
    assert saved.exists()

    with open(saved, encoding="utf-8") as f:
        data = json.load(f)

    assert data["verdict"] == "SHIP"
    assert len(data["warnings"]) == 1
    assert data["warnings"][0]["finding"]["id"] == "f-export"


def test_llm_client_is_configured_logic() -> None:
    """Client should detect whether it is pointed to local or valid cloud API."""
    local_client = LLMClient(base_url="http://localhost:11434/v1", api_key="")
    assert local_client.is_configured is True

    unconfigured_client = LLMClient(base_url="https://api.groq.com/openai/v1", api_key="")
    assert unconfigured_client.is_configured is False

    placeholder_client = LLMClient(
        base_url="https://api.groq.com/openai/v1", api_key="your_api_key_here"
    )
    assert placeholder_client.is_configured is False

    configured_cloud = LLMClient(
        base_url="https://api.groq.com/openai/v1", api_key="gsk_actual_key_12345"
    )
    assert configured_cloud.is_configured is True


import pytest

@pytest.mark.asyncio
async def test_triage_handles_top_level_list_response() -> None:
    """TriageEngine must gracefully process responses whether the LLM returns a dict or top-level list."""
    from unittest.mock import AsyncMock
    from cry.models import TokenUsage

    mock_client = LLMClient(base_url="http://localhost:11434/v1")
    # Simulate LLM returning a raw list instead of {"triage_results": [...]}
    mock_client.chat_completion_json = AsyncMock(  # type: ignore[method-assign]
        return_value=(
            [
                {
                    "finding_id": "f-list-1",
                    "status": "CONFIRMED_BLOCKER",
                    "exploitability_reasoning": "Real exploit path",
                    "plain_english_explanation": "Critical flaw",
                    "fix_recommendation": "Sanitize parameter",
                }
            ],
            TokenUsage(prompt_tokens=50, completion_tokens=30, total_tokens=80),
        )
    )

    finding = Finding(
        id="f-list-1",
        tool="cry-sast",
        title="SQL Injection",
        description="Raw SQL concat",
        category=Category.INJECTION,
        severity=Severity.CRITICAL,
    )

    engine = TriageEngine(client=mock_client)
    report = await engine.triage_findings([finding], FIXTURES_DIR)
    assert report.verdict == Verdict.DONT_SHIP
    assert len(report.blockers) == 1
    assert report.blockers[0].finding.id == "f-list-1"
