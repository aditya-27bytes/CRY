"""Tests for the secrets scanner."""

from pathlib import Path

from cry.models import Category, Severity
from cry.scanners.secrets import scan_directory, scan_file

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_detects_stripe_live_key() -> None:
    """Must detect hardcoded Stripe live secret key."""
    findings = scan_file(FIXTURES_DIR / "vulnerable_app.py", FIXTURES_DIR)
    stripe_findings = [f for f in findings if "Stripe" in f.title]
    assert len(stripe_findings) >= 1
    assert stripe_findings[0].severity == Severity.CRITICAL
    assert stripe_findings[0].category == Category.SECRET_EXPOSURE


def test_detects_aws_access_key() -> None:
    """Must detect AWS Access Key ID (AKIA...)."""
    findings = scan_file(FIXTURES_DIR / "vulnerable_app.py", FIXTURES_DIR)
    aws_findings = [f for f in findings if "AWS" in f.title]
    assert len(aws_findings) >= 1
    assert aws_findings[0].severity == Severity.CRITICAL


def test_detects_database_connection_string() -> None:
    """Must detect database connection string with embedded password."""
    findings = scan_file(FIXTURES_DIR / "vulnerable_app.py", FIXTURES_DIR)
    db_findings = [f for f in findings if "Database" in f.title]
    assert len(db_findings) >= 1
    assert db_findings[0].severity == Severity.CRITICAL


def test_detects_hardcoded_password() -> None:
    """Must detect hardcoded password assignment."""
    findings = scan_file(FIXTURES_DIR / "vulnerable_app.py", FIXTURES_DIR)
    pwd_findings = [f for f in findings if "Password" in f.title or "password" in f.title.lower()]
    assert len(pwd_findings) >= 1


def test_safe_app_has_no_secrets() -> None:
    """Safe app loading secrets from env vars should produce no secret findings."""
    findings = scan_file(FIXTURES_DIR / "safe_app.py", FIXTURES_DIR)
    # Filter to only secret-category findings
    secret_findings = [f for f in findings if f.category == Category.SECRET_EXPOSURE]
    assert len(secret_findings) == 0


def test_redacts_secrets_in_snippet() -> None:
    """Code snippets must partially redact the secret value."""
    findings = scan_file(FIXTURES_DIR / "vulnerable_app.py", FIXTURES_DIR)
    stripe_findings = [f for f in findings if "Stripe" in f.title]
    if stripe_findings:
        snippet = stripe_findings[0].code_snippet or ""
        # The full key should NOT appear in the snippet
        assert "sk_live_4eC39HqLyjWDarjtT1zdp7dc" not in snippet
        # But partial redaction should be visible
        assert "..." in snippet


def test_scan_directory_returns_findings() -> None:
    """Scanning the fixtures directory should return multiple findings."""
    findings = scan_directory(FIXTURES_DIR)
    assert len(findings) > 0
    # All findings should have required fields
    for f in findings:
        assert f.id is not None
        assert f.tool == "cry-secrets"
        assert f.file_path is not None
        assert f.line_start is not None
        assert f.line_start > 0
