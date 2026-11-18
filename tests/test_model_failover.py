"""Unit tests for safe model failover, OpenRouter secondary provider, and Privacy Guard."""

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from cry.cli import _probe_provider_models
from cry.models import Category, Finding, Severity, Verdict
from cry.triage.client import LLMClient, LLMClientError, PrivacyGuardBlockedError
from cry.triage.engine import TriageEngine


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


def test_failover_to_secondary_on_429_when_enabled() -> None:
    """When CRY_FAILOVER=on and primary is throttled (429), failover switches to secondary provider."""
    called_urls: list[str] = []

    async def mock_send(
        url: str, headers: dict[str, str], payload: dict[str, Any]
    ) -> httpx.Response:
        called_urls.append(url)
        if "api.groq.com" in url:
            return httpx.Response(
                status_code=429,
                headers={"retry-after": "0.01"},
                text="Rate limit exceeded: TPM limit hit",
                request=httpx.Request("POST", url),
            )
        elif "openrouter.ai" in url:
            return httpx.Response(
                status_code=200,
                json={
                    "choices": [
                        {"message": {"content": json.dumps({"status": "ok", "triage_results": []})}}
                    ],
                    "usage": {"prompt_tokens": 40, "completion_tokens": 20, "total_tokens": 60},
                },
                request=httpx.Request("POST", url),
            )
        raise ValueError(f"Unexpected url {url}")

    client = LLMClient(
        base_url="https://api.groq.com/openai/v1",
        api_key="gsk_test_key",
        model="llama-3.1-8b-instant",
        fallback_models=[],
        failover_enabled=True,
        secondary_base_url="https://openrouter.ai/api/v1",
        secondary_api_key="sk-or-v1-mock",
        secondary_model="meta-llama/llama-3.3-70b-instruct",
    )
    client._send_request = mock_send  # type: ignore[assignment]

    with patch("asyncio.sleep", return_value=None):
        result, usage = _run_coroutine_sync(
            client.chat_completion_json(
                system_prompt="system",
                user_prompt="user",
                findings_count=3,
            )
        )

    assert result == {"status": "ok", "triage_results": []}
    assert usage.total_tokens == 60
    assert len(client.failover_events) == 1
    ev = client.failover_events[0]
    assert ev.provider == "OpenRouter"
    assert ev.model == "meta-llama/llama-3.3-70b-instruct"
    assert "429" in ev.reason
    assert ev.findings_handled == 3
    assert any("api.groq.com" in u for u in called_urls)
    assert any("openrouter.ai" in u for u in called_urls)


def test_privacy_guard_blocks_cloud_failover_when_primary_is_local() -> None:
    """Privacy Guard must strictly block sending data to external cloud when primary is local (Ollama/localhost)."""
    called_urls: list[str] = []

    async def mock_send(
        url: str, headers: dict[str, str], payload: dict[str, Any]
    ) -> httpx.Response:
        called_urls.append(url)
        return httpx.Response(
            status_code=503,
            headers={"retry-after": "0.01"},
            text="Service Unavailable",
            request=httpx.Request("POST", url),
        )

    client = LLMClient(
        base_url="http://localhost:11434/v1",
        api_key="ollama",
        model="llama3.3:70b",
        fallback_models=[],
        failover_enabled=True,
        secondary_base_url="https://openrouter.ai/api/v1",
        secondary_api_key="sk-or-v1-cloud-key",
        secondary_model="meta-llama/llama-3.3-70b-instruct",
    )
    client._send_request = mock_send  # type: ignore[assignment]

    with (
        patch("asyncio.sleep", return_value=None),
        pytest.raises(PrivacyGuardBlockedError) as exc_info,
    ):
        _run_coroutine_sync(
            client.chat_completion_json(
                system_prompt="system",
                user_prompt="user",
                findings_count=2,
            )
        )

    assert "Privacy Guard" in str(exc_info.value)
    assert "data exfiltration" in str(exc_info.value)
    assert not any("openrouter.ai" in u for u in called_urls)
    assert len(client.failover_events) == 0


def test_no_failover_when_cry_failover_is_disabled() -> None:
    """When CRY_FAILOVER=off (default), client must retry primary but never switch to secondary."""
    called_urls: list[str] = []

    async def mock_send(
        url: str, headers: dict[str, str], payload: dict[str, Any]
    ) -> httpx.Response:
        called_urls.append(url)
        return httpx.Response(
            status_code=429,
            headers={"retry-after": "0.01"},
            text="Rate limit hit",
            request=httpx.Request("POST", url),
        )

    client = LLMClient(
        base_url="https://api.groq.com/openai/v1",
        api_key="gsk_test_key",
        model="llama-3.1-8b-instant",
        fallback_models=[],
        failover_enabled=False,
        max_retries=1,
        secondary_base_url="https://openrouter.ai/api/v1",
        secondary_api_key="sk-or-v1-cloud-key",
        secondary_model="meta-llama/llama-3.3-70b-instruct",
    )
    client._send_request = mock_send  # type: ignore[assignment]

    with patch("asyncio.sleep", return_value=None), pytest.raises(LLMClientError) as exc_info:
        _run_coroutine_sync(
            client.chat_completion_json(
                system_prompt="system",
                user_prompt="user",
            )
        )

    assert "LLM request failed after retries" in str(exc_info.value) or "429" in str(exc_info.value)
    assert not any("openrouter.ai" in u for u in called_urls)
    assert len(client.failover_events) == 0


def test_triage_engine_privacy_guard_graceful_offline_fallback() -> None:
    """TriageEngine must catch PrivacyGuardBlockedError and gracefully fall back to local heuristic."""

    async def mock_send(
        url: str, headers: dict[str, str], payload: dict[str, Any]
    ) -> httpx.Response:
        return httpx.Response(
            status_code=503,
            headers={"retry-after": "0.01"},
            text="Ollama Unavailable",
            request=httpx.Request("POST", url),
        )

    client = LLMClient(
        base_url="http://127.0.0.1:11434/v1",
        api_key="ollama",
        model="llama3.3:70b",
        failover_enabled=True,
        secondary_base_url="https://openrouter.ai/api/v1",
        secondary_api_key="sk-or-v1-secret",
    )
    client._send_request = mock_send  # type: ignore[assignment]
    engine = TriageEngine(client=client)

    findings = [
        Finding(
            id="f-privacy-test",
            tool="cry-sast",
            title="SQL Injection",
            description="SQL vuln in app",
            category=Category.INJECTION,
            severity=Severity.CRITICAL,
            file_path="src/api.py",
            line_start=15,
        )
    ]

    with patch("asyncio.sleep", return_value=None):
        report = _run_coroutine_sync(engine.triage_findings(findings, target_dir=Path(".")))

    assert report.total_raw_findings == 1
    assert len(report.blockers) == 1
    assert report.verdict == Verdict.DONT_SHIP
    assert report.blockers[0].triaged_by_model == "CRY Privacy Guard (Offline Fallback)"
    assert "Privacy Guard" in report.summary


def test_verdict_report_telemetry_captures_failover_events() -> None:
    """VerdictReport must contain structured failover_events telemetry."""

    async def mock_send(
        url: str, headers: dict[str, str], payload: dict[str, Any]
    ) -> httpx.Response:
        if "api.groq.com" in url:
            return httpx.Response(
                status_code=429,
                headers={"retry-after": "0.01"},
                text="Rate limited",
                request=httpx.Request("POST", url),
            )
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
                                            "finding_id": "f-sast-1",
                                            "status": "CONFIRMED_BLOCKER",
                                            "exploitability_reasoning": "Live SQL concatenation",
                                            "plain_english_explanation": "SQL injection",
                                            "fix_recommendation": "Use parameters",
                                        }
                                    ]
                                }
                            )
                        }
                    }
                ],
                "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
            },
            request=httpx.Request("POST", url),
        )

    client = LLMClient(
        base_url="https://api.groq.com/openai/v1",
        api_key="gsk_primary",
        model="llama-3.1-8b-instant",
        fallback_models=[],
        failover_enabled=True,
        secondary_base_url="https://openrouter.ai/api/v1",
        secondary_api_key="sk-or-v1-secondary",
        secondary_model="meta-llama/llama-3.3-70b-instruct",
    )
    client._send_request = mock_send  # type: ignore[assignment]
    engine = TriageEngine(client=client)

    findings = [
        Finding(
            id="f-sast-1",
            tool="cry-sast",
            title="SQL Injection",
            description="Dynamic query",
            category=Category.INJECTION,
            severity=Severity.CRITICAL,
            file_path="src/db.py",
            line_start=20,
        )
    ]

    with patch("asyncio.sleep", return_value=None):
        report = _run_coroutine_sync(engine.triage_findings(findings, target_dir=Path(".")))

    assert len(report.failover_events) == 1
    ev = report.failover_events[0]
    assert ev.provider == "OpenRouter"
    assert ev.model == "meta-llama/llama-3.3-70b-instruct"
    assert ev.findings_handled == 1
    assert len(report.blockers) == 1
    assert report.verdict == Verdict.DONT_SHIP


def test_probe_provider_models_mock(monkeypatch: pytest.MonkeyPatch) -> None:
    """_probe_provider_models must accurately parse /models response or handle errors without network."""

    class MockClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def __enter__(self) -> "MockClient":
            return self

        def __exit__(self, *args: Any) -> None:
            pass

        def get(self, url: str, headers: dict[str, str]) -> httpx.Response:
            if "fail401" in url:
                return httpx.Response(status_code=401, request=httpx.Request("GET", url))
            elif "unreachable" in url:
                raise httpx.ConnectError("Failed to connect")
            return httpx.Response(
                status_code=200,
                json={
                    "data": [
                        {"id": "meta-llama/llama-3.3-70b-instruct"},
                        {"id": "llama-3.1-8b-instant"},
                    ]
                },
                request=httpx.Request("GET", url),
            )

    monkeypatch.setattr(httpx, "Client", MockClient)

    # 1. Successful probe with matching model
    ok, models, msg = _probe_provider_models("https://api.groq.com/openai/v1", "gsk_key")
    assert ok is True
    assert "llama-3.1-8b-instant" in models
    assert "2 model(s) available" in msg

    # 2. 401 Unauthorized probe
    ok, models, msg = _probe_provider_models("https://fail401.com/v1", "bad_key")
    assert ok is False
    assert "401" in msg

    # 3. Connection error
    ok, models, msg = _probe_provider_models("http://unreachable.local/v1", None)
    assert ok is False
    assert "Unreachable" in msg
