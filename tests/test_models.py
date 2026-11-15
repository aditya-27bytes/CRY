"""Tests for the canonical Pydantic models in CRY."""

from cry.models import (
    Category,
    Finding,
    Severity,
    TokenUsage,
    TriagedFinding,
    TriageStatus,
    Verdict,
    VerdictReport,
)


def test_finding_creation() -> None:
    finding = Finding(
        id="finding-001",
        tool="gitleaks",
        title="Hardcoded Stripe Secret Key",
        description="A live Stripe secret key was detected in configuration file.",
        category=Category.SECRET_EXPOSURE,
        severity=Severity.CRITICAL,
        file_path="src/config.ts",
        line_start=14,
        line_end=14,
        code_snippet="const STRIPE_SECRET = 'sk_live_12345';",
        cwe_id="CWE-798",
    )

    assert finding.id == "finding-001"
    assert finding.severity == Severity.CRITICAL
    assert finding.category == Category.SECRET_EXPOSURE
    assert finding.line_start == 14


def test_transparent_triage_preserves_likely_false_positives() -> None:
    """Ensure that findings suspected as false positives are preserved, never dropped."""
    finding = Finding(
        id="finding-002",
        tool="semgrep",
        title="Potential SQL Injection",
        description="Dynamic string formatting detected in query.",
        category=Category.INJECTION,
        severity=Severity.MEDIUM,
        file_path="tests/mock_db.py",
        line_start=10,
        code_snippet="query = f'SELECT * FROM test WHERE id = {val}'",
        cwe_id="CWE-89",
    )

    triaged = TriagedFinding(
        finding=finding,
        status=TriageStatus.LIKELY_FALSE_POSITIVE,
        exploitability_reasoning="Occurs inside test fixture file with static mock data, not exposed to live HTTP traffic.",
        plain_english_explanation="Flagged because it looks like raw SQL, but it only lives in mock test data.",
        fix_recommendation="No action needed unless this test pattern gets copied into production routes.",
    )

    report = VerdictReport(
        verdict=Verdict.SHIP,
        summary="No critical issues found in production paths. 1 test-fixture pattern noted.",
        target="./my-app",
        total_raw_findings=1,
        likely_false_positives=[triaged],
        token_usage=TokenUsage(
            prompt_tokens=420, completion_tokens=85, total_tokens=505, estimated_cost_usd=0.0003
        ),
    )

    assert report.verdict == Verdict.SHIP
    assert len(report.blockers) == 0
    # Must remain visible in likely_false_positives!
    assert len(report.likely_false_positives) == 1
    assert report.likely_false_positives[0].status == TriageStatus.LIKELY_FALSE_POSITIVE
    assert report.token_usage.total_tokens == 505
