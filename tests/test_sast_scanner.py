"""Tests for the SAST code pattern scanner."""

from pathlib import Path

from cry.models import Category, Severity
from cry.scanners.sast import scan_directory, scan_file

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_detects_sql_injection() -> None:
    """Must detect SQL injection via f-string/concatenation."""
    findings = scan_file(FIXTURES_DIR / "vulnerable_app.py", FIXTURES_DIR)
    sqli_findings = [f for f in findings if f.cwe_id == "CWE-89"]
    assert len(sqli_findings) >= 1
    assert sqli_findings[0].severity == Severity.CRITICAL
    assert sqli_findings[0].category == Category.INJECTION


def test_detects_command_injection() -> None:
    """Must detect os.system and subprocess with shell=True."""
    findings = scan_file(FIXTURES_DIR / "vulnerable_app.py", FIXTURES_DIR)
    cmdi_findings = [f for f in findings if f.cwe_id == "CWE-78"]
    assert len(cmdi_findings) >= 1
    assert cmdi_findings[0].severity == Severity.CRITICAL


def test_detects_eval_usage() -> None:
    """Must detect dangerous eval() calls."""
    findings = scan_file(FIXTURES_DIR / "vulnerable_app.py", FIXTURES_DIR)
    eval_findings = [f for f in findings if f.cwe_id == "CWE-95"]
    assert len(eval_findings) >= 1


def test_detects_unsafe_deserialization() -> None:
    """Must detect pickle.loads()."""
    findings = scan_file(FIXTURES_DIR / "vulnerable_app.py", FIXTURES_DIR)
    deser_findings = [f for f in findings if f.cwe_id == "CWE-502"]
    assert len(deser_findings) >= 1


def test_detects_debug_mode() -> None:
    """Must detect debug mode enabled."""
    findings = scan_file(FIXTURES_DIR / "vulnerable_app.py", FIXTURES_DIR)
    debug_findings = [f for f in findings if f.cwe_id == "CWE-215"]
    assert len(debug_findings) >= 1


def test_detects_disabled_ssl() -> None:
    """Must detect verify=False."""
    findings = scan_file(FIXTURES_DIR / "vulnerable_app.py", FIXTURES_DIR)
    ssl_findings = [f for f in findings if f.cwe_id == "CWE-295"]
    assert len(ssl_findings) >= 1


def test_detects_cors_wildcard() -> None:
    """Must detect CORS wildcard '*'."""
    findings = scan_file(FIXTURES_DIR / "vulnerable_app.py", FIXTURES_DIR)
    cors_findings = [f for f in findings if f.cwe_id == "CWE-942"]
    assert len(cors_findings) >= 1


def test_detects_csrf_disabled() -> None:
    """Must detect CSRF protection disabled."""
    findings = scan_file(FIXTURES_DIR / "vulnerable_app.py", FIXTURES_DIR)
    csrf_findings = [f for f in findings if f.cwe_id == "CWE-352"]
    assert len(csrf_findings) >= 1


def test_safe_app_has_minimal_findings() -> None:
    """Safe app with correct practices should produce very few or zero SAST findings."""
    findings = scan_file(FIXTURES_DIR / "safe_app.py", FIXTURES_DIR)
    # No critical or high severity findings expected
    critical_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert len(critical_high) == 0


def test_scan_directory_finds_issues() -> None:
    """Scanning the fixtures directory should detect issues in vulnerable files."""
    findings = scan_directory(FIXTURES_DIR)
    assert len(findings) > 0
    for f in findings:
        assert f.tool == "cry-sast"
        assert f.file_path is not None
        assert f.line_start is not None
