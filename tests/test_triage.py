"""Tests for the triage engine and reporters."""

import json
from pathlib import Path
from typing import Any

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
from cry.reporters.terminal import print_verdict_report
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


def test_extract_llm_triage_results_handles_all_shapes() -> None:
    """Triage parser must handle top-level list, dict wrappers, single findings, and invalid inputs."""
    from cry.triage.engine import extract_llm_triage_results

    # 1. Top-level list response (e.g. from gpt-oss-120b or Ollama)
    raw_list = [
        {"finding_id": "f-1", "status": "CONFIRMED_BLOCKER"},
        {"finding_id": "f-2", "status": "WARNING"},
    ]
    assert extract_llm_triage_results(raw_list) == raw_list

    # 2. Standard dict with 'triage_results' key
    dict_results = {"triage_results": [{"finding_id": "f-1", "status": "CONFIRMED_BLOCKER"}]}
    assert extract_llm_triage_results(dict_results) == [
        {"finding_id": "f-1", "status": "CONFIRMED_BLOCKER"}
    ]

    # 3. Dict with 'findings' key
    dict_findings = {"findings": [{"finding_id": "f-3", "status": "LIKELY_FALSE_POSITIVE"}]}
    assert extract_llm_triage_results(dict_findings) == [
        {"finding_id": "f-3", "status": "LIKELY_FALSE_POSITIVE"}
    ]

    # 4. Dict with 'results' key
    dict_alt = {"results": [{"finding_id": "f-4", "status": "WARNING"}]}
    assert extract_llm_triage_results(dict_alt) == [{"finding_id": "f-4", "status": "WARNING"}]

    # 5. Single item dict without wrapper
    single_item = {"finding_id": "f-5", "status": "CONFIRMED_BLOCKER"}
    assert extract_llm_triage_results(single_item) == [single_item]

    # 6. Malformed entries filtered out cleanly
    malformed_list = [
        None,
        "not a dict",
        {"no_finding_id": True},
        {"finding_id": "", "status": "IGNORED"},
        {"finding_id": "f-valid", "status": "CONFIRMED_BLOCKER"},
    ]
    assert extract_llm_triage_results(malformed_list) == [
        {"finding_id": "f-valid", "status": "CONFIRMED_BLOCKER"}
    ]

    # 7. Non-iterable / empty values
    assert extract_llm_triage_results(None) == []
    assert extract_llm_triage_results("raw string") == []
    assert extract_llm_triage_results(12345) == []


def test_settings_get_fallback_candidates() -> None:
    """Settings must provide prioritized alternative models excluding current active model."""
    from cry.config import settings

    # Groq endpoint fallback candidates
    groq_fallbacks = settings.get_fallback_candidates(
        base_url="https://api.groq.com/openai/v1", current_model="openai/gpt-oss-120b"
    )
    assert "openai/gpt-oss-120b" not in groq_fallbacks
    assert "qwen/qwen3.8-27b" in groq_fallbacks
    assert "llama-3.1-8b-instant" in groq_fallbacks

    # OpenAI endpoint fallback candidates
    openai_fallbacks = settings.get_fallback_candidates(
        base_url="https://api.openai.com/v1", current_model="gpt-4o"
    )
    assert "gpt-4o" not in openai_fallbacks
    assert "gpt-4o-mini" in openai_fallbacks


def _run_coroutine_sync(coro: Any) -> Any:
    """Synchronously execute a coroutine without requiring an asyncio event loop or socket connections."""
    stack = [coro]
    result = None
    while stack:
        try:
            val = stack[-1].send(result)
            if hasattr(val, "send"):
                stack.append(val)
                result = None
            else:
                result = val
        except StopIteration as e:
            stack.pop()
            result = e.value
    return result


def test_llm_client_dynamic_model_failover_on_429() -> None:
    """Client must dynamically fail over to fallback model when primary model hits HTTP 429 rate limit."""
    import httpx

    client = LLMClient(
        base_url="https://api.groq.com/openai/v1",
        api_key="gsk_test_mock_12345",
        model="openai/gpt-oss-120b",
        fallback_models=["qwen/qwen3.8-27b"],
        max_retries=1,
    )

    req_count = 0

    async def mock_send(
        url: str, headers: dict[str, str], payload: dict[str, Any]
    ) -> httpx.Response:
        nonlocal req_count
        req_count += 1
        model_sent = payload.get("model", "")
        if model_sent == "openai/gpt-oss-120b":
            # Primary model hits rate limit
            return httpx.Response(
                status_code=429,
                headers={"retry-after": "1"},
                json={"error": {"message": "Rate limit exceeded (TPM)"}},
                request=httpx.Request("POST", url),
            )
        else:
            # Fallback model succeeds
            return httpx.Response(
                status_code=200,
                json={
                    "choices": [{"message": {"content": '{"triage_results": []}'}}],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                },
                request=httpx.Request("POST", url),
            )

    client._send_request = mock_send  # type: ignore[method-assign]
    data, usage = _run_coroutine_sync(
        client.chat_completion_json(system_prompt="sys", user_prompt="user")
    )

    assert data == {"triage_results": []}
    assert client.model == "qwen/qwen3.8-27b"  # Model updated to working fallback
    assert len(client.switched_models_log) > 0
    assert "openai/gpt-oss-120b" in client.switched_models_log[0]
    assert req_count == 2


def test_llm_client_dynamic_model_failover_on_404() -> None:
    """Client must drop decommissioned model on HTTP 404 and fail over seamlessly."""
    import httpx

    client = LLMClient(
        base_url="https://api.groq.com/openai/v1",
        api_key="gsk_test_mock_12345",
        model="retired/legacy-model-v1",
        fallback_models=["openai/gpt-oss-120b"],
        max_retries=1,
    )

    async def mock_send(
        url: str, headers: dict[str, str], payload: dict[str, Any]
    ) -> httpx.Response:
        model_sent = payload.get("model", "")
        if "retired" in model_sent:
            return httpx.Response(
                status_code=404,
                json={"error": {"message": "Model not found"}},
                request=httpx.Request("POST", url),
            )
        return httpx.Response(
            status_code=200,
            json={
                "choices": [{"message": {"content": '{"triage_results": []}'}}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 6, "total_tokens": 18},
            },
            request=httpx.Request("POST", url),
        )

    client._send_request = mock_send  # type: ignore[method-assign]
    data, usage = _run_coroutine_sync(
        client.chat_completion_json(system_prompt="sys", user_prompt="user")
    )

    assert data == {"triage_results": []}
    assert client.model == "openai/gpt-oss-120b"
    assert len(client.switched_models_log) > 0


def test_llm_client_retry_round_after_all_models_throttled() -> None:
    """Client must wait and retry on round 2 without raising UnboundLocalError when round 1 throttles."""
    from unittest.mock import patch

    import httpx

    client = LLMClient(
        base_url="https://api.groq.com/openai/v1",
        api_key="gsk_test_mock_12345",
        model="llama-3.1-8b-instant",
        fallback_models=[],  # No alternative models, forces retry round
        max_retries=1,
    )

    attempt = 0

    async def mock_send(
        url: str, headers: dict[str, str], payload: dict[str, Any]
    ) -> httpx.Response:
        nonlocal attempt
        attempt += 1
        if attempt == 1:
            # Round 0: 429 rate limit
            return httpx.Response(
                status_code=429,
                headers={"retry-after": "0.01"},
                json={"error": {"message": "Rate limit reached"}},
                request=httpx.Request("POST", url),
            )
        # Round 1: success
        return httpx.Response(
            status_code=200,
            json={
                "choices": [{"message": {"content": '{"triage_results": []}'}}],
                "usage": {"prompt_tokens": 15, "completion_tokens": 8, "total_tokens": 23},
            },
            request=httpx.Request("POST", url),
        )

    client._send_request = mock_send  # type: ignore[method-assign]
    with patch("asyncio.sleep", return_value=None):
        data, usage = _run_coroutine_sync(
            client.chat_completion_json(system_prompt="sys", user_prompt="user")
        )

    assert data == {"triage_results": []}
    assert attempt == 2


def test_smart_hybrid_routing_partitions_secrets_and_test_mocks() -> None:
    """Smart routing must deterministically triage secrets and test fixtures, forwarding only app SAST to LLM."""
    import httpx

    client = LLMClient(
        base_url="https://api.groq.com/openai/v1",
        api_key="gsk_mock_test_key",
        model="llama-3.1-8b-instant",
    )

    llm_call_count = 0

    async def mock_send(
        url: str, headers: dict[str, str], payload: dict[str, Any]
    ) -> httpx.Response:
        nonlocal llm_call_count
        llm_call_count += 1
        # The LLM should only receive finding f-real-sast
        return httpx.Response(
            status_code=200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "triage_results": [
                                        {
                                            "finding_id": "f-real-sast",
                                            "status": "CONFIRMED_BLOCKER",
                                            "exploitability_reasoning": "Live unescaped SQL concat",
                                            "plain_english_explanation": "Critical SQL injection",
                                            "fix_recommendation": "Use parameter binding",
                                        }
                                    ]
                                }
                            )
                        }
                    }
                ],
                "usage": {"prompt_tokens": 50, "completion_tokens": 30, "total_tokens": 80},
            },
            request=httpx.Request("POST", url),
        )

    client._send_request = mock_send  # type: ignore[method-assign]
    engine = TriageEngine(client=client)

    findings = [
        # 1. Real Secret in production code -> Deterministic CONFIRMED_BLOCKER
        Finding(
            id="f-prod-secret",
            tool="cry-secrets",
            title="Stripe Key",
            description="Live key",
            category=Category.SECRET_EXPOSURE,
            severity=Severity.CRITICAL,
            file_path="src/config.py",
            line_start=1,
        ),
        # 2. Mock Secret in test file -> Deterministic LIKELY_FALSE_POSITIVE
        Finding(
            id="f-test-secret",
            tool="cry-secrets",
            title="Stripe Key",
            description="Test key",
            category=Category.SECRET_EXPOSURE,
            severity=Severity.CRITICAL,
            file_path="tests/fixtures/test_env.py",
            line_start=1,
        ),
        # 3. Test SAST finding -> Deterministic LIKELY_FALSE_POSITIVE
        Finding(
            id="f-test-sast",
            tool="cry-sast",
            title="Mock SQLi",
            description="SQL in mock",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            file_path="tests/mock_db.py",
            line_start=1,
        ),
        # 4. Real SAST finding in app code -> Must be routed to LLM
        Finding(
            id="f-real-sast",
            tool="cry-sast",
            title="SQL Injection",
            description="SQL flaw in routes",
            category=Category.INJECTION,
            severity=Severity.CRITICAL,
            file_path="src/routes/users.py",
            line_start=1,
        ),
    ]

    report = _run_coroutine_sync(engine.triage_findings(findings, target_dir=Path(".")))

    # Verify LLM was invoked exactly once for the single real app flaw
    assert llm_call_count == 1
    assert report.total_raw_findings == 4
    assert len(report.blockers) == 2  # f-prod-secret (deterministic) + f-real-sast (LLM)
    assert len(report.warnings) == 2  # f-test-secret + f-test-sast (non-blocking test advisories)
    assert report.verdict == Verdict.DONT_SHIP


def test_test_fixtures_only_yield_warning_not_dont_ship() -> None:
    """Findings located exclusively in test/mock/fixture directories must never block deployment."""
    engine = TriageEngine(client=LLMClient(api_key=""))
    findings = [
        Finding(
            id="f-fixture-sql",
            tool="cry-sast",
            title="SQL Injection",
            description="SQL in fixture",
            category=Category.INJECTION,
            severity=Severity.CRITICAL,
            file_path="tests/fixtures/vulnerable_app.py",
            line_start=18,
        ),
        Finding(
            id="f-fixture-secret",
            tool="cry-secrets",
            title="Stripe Key",
            description="Dummy Stripe Key",
            category=Category.SECRET_EXPOSURE,
            severity=Severity.CRITICAL,
            file_path="tests/fixtures/vulnerable_app.py",
            line_start=9,
        ),
    ]

    # Offline heuristic evaluation
    heuristic_report = engine._heuristic_fallback(findings, target_dir=Path("."))
    assert len(heuristic_report.blockers) == 0
    assert len(heuristic_report.warnings) == 2
    assert heuristic_report.verdict == Verdict.FIX_FIRST
    assert "TEST/MOCK WARNINGS" in heuristic_report.summary

    # Async smart hybrid triage evaluation
    ai_report = _run_coroutine_sync(engine.triage_findings(findings, target_dir=Path(".")))
    assert len(ai_report.blockers) == 0
    assert len(ai_report.warnings) == 2
    assert ai_report.verdict == Verdict.FIX_FIRST
    assert "TEST/MOCK WARNINGS" in ai_report.summary


def test_print_verdict_report_compact_warnings_overflow(capsys: Any) -> None:
    """When warnings exceed max_compact_warnings, output must cap and summarize remaining."""
    warnings: list[TriagedFinding] = []
    for i in range(25):
        f = Finding(
            id=f"w-{i}",
            tool="cry-sast",
            title="Insecure Randomness" if i % 2 == 0 else "Debug Mode",
            description=f"Warning detail {i}",
            category=Category.MISCONFIGURATION,
            severity=Severity.MEDIUM,
            file_path=f"tests/test_{i}.py",
            line_start=10 + i,
        )
        warnings.append(
            TriagedFinding(
                finding=f,
                status=TriageStatus.WARNING,
                plain_english_explanation=f"Advisory explanation {i}",
                exploitability_reasoning=f"Reasoning {i}",
                fix_recommendation=f"Fix recommendation {i}",
            )
        )

    report = VerdictReport(
        verdict=Verdict.FIX_FIRST,
        summary="Test summary",
        target=".",
        blockers=[],
        warnings=warnings,
        likely_false_positives=[],
    )

    print_verdict_report(report)
    out = capsys.readouterr().out

    # Top 10 shown, remaining 15 summarized
    assert "Showing top 10 of 25" in out
    assert "15 additional advisory warning" in out
    assert "Insecure Randomness" in out
    assert "VERDICT: FIX FIRST" in out
    assert "0 Blockers, 25 Warnings" in out


def test_print_verdict_report_all_findings_expands_all(capsys: Any) -> None:
    """When all_findings is True, all warnings must be rendered without truncation."""
    warnings: list[TriagedFinding] = []
    for i in range(15):
        f = Finding(
            id=f"w-{i}",
            tool="cry-sast",
            title="Advisory Rule",
            description=f"Warning detail {i}",
            category=Category.MISCONFIGURATION,
            severity=Severity.LOW,
            file_path=f"tests/test_{i}.py",
            line_start=10 + i,
        )
        warnings.append(
            TriagedFinding(
                finding=f,
                status=TriageStatus.WARNING,
                plain_english_explanation=f"Advisory explanation {i}",
                exploitability_reasoning=f"Reasoning {i}",
                fix_recommendation=f"Fix recommendation {i}",
            )
        )

    report = VerdictReport(
        verdict=Verdict.FIX_FIRST,
        summary="Test summary",
        target=".",
        blockers=[],
        warnings=warnings,
        likely_false_positives=[],
    )

    print_verdict_report(report, all_findings=True)
    out = capsys.readouterr().out

    assert "Warnings & Advisories (15 items)" in out
    assert "omitted from terminal view" not in out
    assert "VERDICT: FIX FIRST" in out


def test_print_verdict_report_blockers_capping_and_sticky_footer(capsys: Any) -> None:
    """Blockers exceeding 5 must display top 5 detailed and remaining in compact table."""
    blockers: list[TriagedFinding] = []
    for i in range(12):
        f = Finding(
            id=f"b-{i}",
            tool="cry-secrets",
            title="AWS Access Key",
            description=f"Secret leak {i}",
            category=Category.SECRET_EXPOSURE,
            severity=Severity.CRITICAL,
            file_path=f"src/config_{i}.py",
            line_start=5 + i,
            code_snippet=f"AWS_KEY_{i} = 'AKIA12345'",
        )
        blockers.append(
            TriagedFinding(
                finding=f,
                status=TriageStatus.CONFIRMED_BLOCKER,
                plain_english_explanation=f"Exposed AWS Key {i}",
                exploitability_reasoning=f"Critical threat vector {i}",
                fix_recommendation="Use env var",
                suggested_replacement_code=f"os.environ['AWS_KEY_{i}']",
            )
        )

    report = VerdictReport(
        verdict=Verdict.DONT_SHIP,
        summary="Critical blockers found",
        target=".",
        blockers=blockers,
        warnings=[],
        likely_false_positives=[],
    )

    print_verdict_report(report)
    out = capsys.readouterr().out

    assert "Critical Blockers (12 issues)" in out
    assert "Additional Critical Blockers (7 more)" in out
    assert "VERDICT: DON'T SHIP" in out
    assert "12 Blockers, 0 Warnings" in out


def test_print_verdict_report_safe_to_ship(capsys: Any) -> None:
    """Safe to ship reports must print clean verdict panel with zero blockers and warnings."""
    report = VerdictReport(
        verdict=Verdict.SHIP,
        summary="No blockers found",
        target=".",
        blockers=[],
        warnings=[],
        likely_false_positives=[],
    )

    print_verdict_report(report)
    out = capsys.readouterr().out

    assert "SAFE TO SHIP" in out
    assert "0 Blockers, 0 Warnings" in out
    assert "Your application is safe to ship!" in out
