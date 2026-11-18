"""Comprehensive tests for v0.4 security rules expansion:
- Secrets catalog (OpenRouter, Anthropic, Pinecone, LangSmith, Replicate, Cohere, Together)
- Web & Framework SAST (Flask SSTI, Prisma raw SQL, JWT verification disabled, CORS reflection, Vue v-html)
- AI & LLM Application rules (Prompt injection, excessive agency, unvalidated exec sink, RAG, frontend AI)
"""

from pathlib import Path

import pytest

from cry.models import Severity
from cry.scanners.sast import scan_file as scan_file_sast
from cry.scanners.secrets import scan_file as scan_file_secrets

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "v04_rules"


@pytest.fixture
def vulnerable_secrets_file(tmp_path: Path) -> Path:
    """Dynamically generate vulnerable secrets test file at runtime to prevent git push protection false positives."""
    p = tmp_path / "vulnerable_secrets.py"
    or_token = "sk-or-v1-" + "0123456789abcdef" * 4
    ant_token = (
        "sk-ant-api03-"
        + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-abcdefghijklmnopqrstuvwxyzAA"
    )
    cohere_token = "aBcDeFgHiJkLmNoPqRsTuVwXyZ" + "0123456789AbCd"
    together_token = "0123456789abcdef" * 4

    p.write_text(
        f"""# Dynamic test fixture: vulnerable AI and cloud secrets for v0.4 rules

OPENROUTER_KEY = "{or_token}"
ANTHROPIC_KEY = "{ant_token}"
PINECONE_KEY = "pcsk_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
LANGSMITH_KEY = "lsv2_pt_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF0123456789"
REPLICATE_KEY = "r8_abcdefghijklmnopqrstuvwxyz0123456789A"
cohere_key = "{cohere_token}"
together_key = "{together_token}"
""",
        encoding="utf-8",
    )
    return p


def test_v04_secrets_detected_in_vulnerable_fixture(vulnerable_secrets_file: Path) -> None:
    """Verifies that high-confidence prefix-based and context-based secrets are detected."""
    findings = scan_file_secrets(vulnerable_secrets_file, vulnerable_secrets_file.parent)

    titles = [f.title for f in findings]
    assert any("OpenRouter" in t for t in titles), f"OpenRouter missed: {titles}"
    assert any("Anthropic" in t for t in titles), f"Anthropic missed: {titles}"
    assert any("Pinecone" in t for t in titles), f"Pinecone missed: {titles}"
    assert any("LangSmith" in t for t in titles), f"LangSmith missed: {titles}"
    assert any("Replicate" in t for t in titles), f"Replicate missed: {titles}"
    assert any("Cohere" in t for t in titles), f"Cohere missed: {titles}"
    assert any("Together" in t for t in titles), f"Together missed: {titles}"

    # Verify context-based patterns are LOW severity warnings, never blockers
    cohere_finding = next(f for f in findings if "Cohere" in f.title)
    assert cohere_finding.severity == Severity.LOW
    assert cohere_finding.confidence <= 0.5

    together_finding = next(f for f in findings if "Together" in f.title)
    assert together_finding.severity == Severity.LOW
    assert together_finding.confidence <= 0.5

    # Verify secrets masking (never print in full)
    or_full = "sk-or-v1-" + "0123456789abcdef" * 4
    ant_full = (
        "sk-ant-api03-"
        + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-abcdefghijklmnopqrstuvwxyzAA"
    )
    for f in findings:
        assert or_full not in (f.code_snippet or "")
        assert ant_full not in (f.code_snippet or "")


def test_v04_secrets_safe_fixture_clean() -> None:
    """Safe secrets usage via os.environ must produce zero findings."""
    safe_file = FIXTURES_DIR / "safe_secrets.py"
    findings = scan_file_secrets(safe_file, FIXTURES_DIR)
    assert len(findings) == 0, f"Expected 0 findings in safe_secrets.py, got: {findings}"


def test_v04_web_sast_vulnerable_fixture() -> None:
    """Verifies Flask SSTI, JWT disabled, CORS origin reflection, Prisma SQLi, and Vue v-html."""
    py_vuln = FIXTURES_DIR / "vulnerable_web.py"
    findings_py = scan_file_sast(py_vuln, FIXTURES_DIR)
    titles_py = [f.title for f in findings_py]

    assert any("Jinja2" in t or "Template Injection" in t for t in titles_py), (
        f"SSTI missed: {titles_py}"
    )
    assert any("JWT" in t and "Disabled" in t for t in titles_py), (
        f"JWT disabled missed: {titles_py}"
    )
    assert any("CORS" in t for t in titles_py), f"CORS reflection missed: {titles_py}"

    ts_vuln = FIXTURES_DIR / "vulnerable_web.ts"
    findings_ts = scan_file_sast(ts_vuln, FIXTURES_DIR)
    titles_ts = [f.title for f in findings_ts]

    assert any("Prisma" in t for t in titles_ts), f"Prisma raw query missed: {titles_ts}"
    assert any("v-html" in t for t in titles_ts), f"Vue v-html missed: {titles_ts}"


def test_v04_web_sast_safe_fixture() -> None:
    """Safe web fixtures must produce zero false alarms."""
    py_safe = FIXTURES_DIR / "safe_web.py"
    findings_py = scan_file_sast(py_safe, FIXTURES_DIR)
    assert len(findings_py) == 0, f"False alarm in safe_web.py: {[f.title for f in findings_py]}"

    ts_safe = FIXTURES_DIR / "safe_web.ts"
    findings_ts = scan_file_sast(ts_safe, FIXTURES_DIR)
    assert len(findings_ts) == 0, f"False alarm in safe_web.ts: {[f.title for f in findings_ts]}"


def test_v04_ai_sast_vulnerable_fixture() -> None:
    """Verifies Prompt injection, excessive agency tool, unvalidated exec sink, and frontend AI client."""
    ai_vuln = FIXTURES_DIR / "vulnerable_ai.py"
    findings_ai = scan_file_sast(ai_vuln, FIXTURES_DIR)
    titles_ai = [f.title for f in findings_ai]

    assert any("Prompt Injection" in t for t in titles_ai), f"Prompt injection missed: {titles_ai}"
    assert any("Excessive Agency" in t for t in titles_ai), (
        f"Excessive agency tool missed: {titles_ai}"
    )
    assert any("Unvalidated LLM Output" in t or "Execution Sink" in t for t in titles_ai), (
        f"Unvalidated exec sink missed: {titles_ai}"
    )
    assert any("RAG" in t for t in titles_ai), f"RAG ingestion missed: {titles_ai}"

    # Verify severity distinctions:
    exec_sink = next(
        f for f in findings_ai if "Unvalidated LLM Output" in f.title or "Execution Sink" in f.title
    )
    assert exec_sink.severity == Severity.CRITICAL  # Blocker when output reaches exec sink

    agency_tool = next(f for f in findings_ai if "Excessive Agency" in f.title)
    assert agency_tool.severity == Severity.MEDIUM  # Warning/medium for tool that merely exists

    frontend_vuln = FIXTURES_DIR / "vulnerable_frontend.ts"
    findings_frontend = scan_file_sast(frontend_vuln, FIXTURES_DIR)
    titles_frontend = [f.title for f in findings_frontend]
    assert any("AI Client" in t or "System Prompt" in t for t in titles_frontend), (
        f"Frontend AI missed: {titles_frontend}"
    )


def test_v04_ai_sast_safe_fixture() -> None:
    """Safe AI fixtures must produce zero false alarms."""
    ai_safe = FIXTURES_DIR / "safe_ai.py"
    findings_ai = scan_file_sast(ai_safe, FIXTURES_DIR)
    assert len(findings_ai) == 0, f"False alarm in safe_ai.py: {[f.title for f in findings_ai]}"

    frontend_safe = FIXTURES_DIR / "safe_frontend.ts"
    findings_frontend = scan_file_sast(frontend_safe, FIXTURES_DIR)
    assert len(findings_frontend) == 0, (
        f"False alarm in safe_frontend.ts: {[f.title for f in findings_frontend]}"
    )
