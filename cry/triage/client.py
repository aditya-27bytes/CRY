"""OpenAI-compatible LLM client for CRY with dynamic multi-model resilience.

Supports any provider with an OpenAI-compatible endpoint:
- Groq Cloud: https://api.groq.com/openai/v1
- Local Ollama: http://localhost:11434/v1
- Local vLLM: http://localhost:8000/v1
- OpenAI: https://api.openai.com/v1

Features:
- Dynamic fallback & failover when hitting API rate limits (HTTP 429 / TPM limits)
- Automatic model deprecation recovery (HTTP 404)
- Retry-after header and response backoff parsing
- Multi-model audit logging for complete developer transparency
"""

import asyncio
import contextlib
import json
import re
from typing import Any

import httpx

from cry.config import settings
from cry.models import FailoverEvent, TokenUsage


class LLMClientError(Exception):
    """Raised when the LLM provider fails to generate a response."""

    pass


class PrivacyGuardBlockedError(LLMClientError):
    """Raised when Privacy Guard blocks failover from a local LLM to a cloud provider."""

    pass


class LLMClient:
    """Lightweight, resilient OpenAI-compatible chat completion client with dynamic model failover."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        fallback_models: list[str] | None = None,
        timeout: float = 15.0,
        max_retries: int = 2,
        failover_enabled: bool | None = None,
        secondary_base_url: str | None = None,
        secondary_api_key: str | None = None,
        secondary_model: str | None = None,
    ) -> None:
        self.base_url = (base_url or settings.LLM_BASE_URL).rstrip("/")
        self.api_key = api_key if api_key is not None else settings.LLM_API_KEY
        self.model = model or settings.LLM_MODEL
        self.timeout = timeout if timeout != 15.0 else 60.0
        self.max_retries = max_retries
        self.failover_enabled = (
            failover_enabled if failover_enabled is not None else settings.FAILOVER_ENABLED
        )
        self.secondary_base_url = (secondary_base_url or settings.SECONDARY_BASE_URL).rstrip("/")
        self.secondary_api_key = (
            secondary_api_key if secondary_api_key is not None else settings.SECONDARY_API_KEY
        )
        self.secondary_model = secondary_model or settings.SECONDARY_MODEL

        self.switched_models_log: list[str] = []
        self.failover_events: list[FailoverEvent] = []
        self._secondary_active: bool = False

        if fallback_models is not None:
            self.fallback_models = [m for m in fallback_models if m != self.model]
        else:
            self.fallback_models = settings.get_fallback_candidates(self.base_url, self.model)

    @property
    def is_configured(self) -> bool:
        """Check if client has a local endpoint or a non-empty API key."""
        if settings.is_local_endpoint(self.base_url):
            return True
        return bool(self.api_key and not self.api_key.startswith("your_"))

    @property
    def is_local(self) -> bool:
        """Check if client is pointing to a local offline endpoint."""
        return settings.is_local_endpoint(self.base_url)

    @property
    def has_secondary(self) -> bool:
        """Check if secondary failover provider is configured."""
        if settings.is_local_endpoint(self.secondary_base_url):
            return True
        return bool(self.secondary_api_key and not self.secondary_api_key.startswith("your_"))

    @property
    def is_secondary_local(self) -> bool:
        """Check if secondary failover provider is a local endpoint."""
        return settings.is_local_endpoint(self.secondary_base_url)

    async def _send_request(
        self, url: str, headers: dict[str, str], payload: dict[str, Any]
    ) -> httpx.Response:
        """Send HTTP POST request to LLM endpoint."""
        async with httpx.AsyncClient(timeout=httpx.Timeout(self.timeout, connect=5.0)) as client:
            return await client.post(url, headers=headers, json=payload)

    async def _execute_completion(
        self,
        base_url: str,
        api_key: str | None,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
    ) -> tuple[dict[str, Any], TokenUsage]:
        """Execute a single JSON completion request against a specified provider endpoint."""
        headers: dict[str, str] = {
            "Content-Type": "application/json",
        }
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        if "openrouter.ai" in base_url.lower():
            headers["HTTP-Referer"] = "https://github.com/aditya-27bytes/CRY"
            headers["X-Title"] = "CRY Security Scanner"

        url = f"{base_url}/chat/completions"
        payload: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": 4096,
            "response_format": {"type": "json_object"},
        }

        response = await self._send_request(url, headers=headers, payload=payload)
        response.raise_for_status()
        data = response.json()

        try:
            content_str = data["choices"][0]["message"]["content"]
            result_json = json.loads(content_str)
        except (KeyError, IndexError, json.JSONDecodeError) as e:
            raise LLMClientError(f"Invalid JSON response from LLM at {url}: {e}") from e

        usage_data = data.get("usage", {})
        prompt_tokens = usage_data.get("prompt_tokens", 0)
        completion_tokens = usage_data.get("completion_tokens", 0)
        total_tokens = usage_data.get("total_tokens", prompt_tokens + completion_tokens)

        cost_prompt = (prompt_tokens / 1_000_000) * settings.COST_PER_MILLION_PROMPT_TOKENS
        cost_completion = (
            completion_tokens / 1_000_000
        ) * settings.COST_PER_MILLION_COMPLETION_TOKENS
        estimated_cost = round(cost_prompt + cost_completion, 6)

        usage = TokenUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            estimated_cost_usd=estimated_cost,
        )
        return result_json, usage

    async def chat_completion_json(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        allow_model_switching: bool = True,
        findings_count: int = 0,
    ) -> tuple[dict[str, Any], TokenUsage]:
        """Request a structured JSON completion with multi-model and secondary provider failover."""
        if not self.is_configured:
            raise LLMClientError(
                "LLM provider is not configured. Set CRY_LLM_API_KEY in .env "
                "or point CRY_LLM_BASE_URL to http://localhost:11434/v1 for local Ollama."
            )

        # 1. If failover to secondary provider has already been triggered in an earlier batch
        if self._secondary_active:
            try:
                res, usage = await self._execute_completion(
                    base_url=self.secondary_base_url,
                    api_key=self.secondary_api_key,
                    model=self.secondary_model,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    temperature=temperature,
                )
                if self.failover_events:
                    self.failover_events[-1].findings_handled += findings_count
                return res, usage
            except Exception as e:
                raise LLMClientError(
                    f"Secondary provider ({self.secondary_base_url}) failed: {e}"
                ) from e

        # 2. Try Primary Provider (with candidate queue and retry)
        candidate_queue: list[str] = [self.model]
        if allow_model_switching:
            for fb in self.fallback_models:
                if fb not in candidate_queue:
                    candidate_queue.append(fb)

        last_error: Exception | None = None
        status_code_for_failover: int | None = None

        for attempt in range(self.max_retries + 1):
            idx = 0
            while idx < len(candidate_queue):
                target_model = candidate_queue[idx]
                try:
                    res, usage = await self._execute_completion(
                        base_url=self.base_url,
                        api_key=self.api_key,
                        model=target_model,
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        temperature=temperature,
                    )
                    if target_model != self.model:
                        switch_info = f"Active model switched from '{self.model}' to '{target_model}' on primary provider"
                        if switch_info not in self.switched_models_log:
                            self.switched_models_log.append(switch_info)
                        self.model = target_model
                    return res, usage

                except httpx.HTTPStatusError as e:
                    last_error = e
                    status_code = e.response.status_code
                    resp_text = e.response.text

                    if status_code == 401:
                        raise LLMClientError(
                            "Invalid or unauthorized API key (HTTP 401). "
                            "Please run 'cry configure' or check CRY_LLM_API_KEY in .env."
                        ) from e

                    elif status_code == 404:
                        candidate_queue.pop(idx)
                        continue

                    elif status_code == 429 or status_code in (502, 503, 504):
                        status_code_for_failover = status_code
                        if allow_model_switching and idx + 1 < len(candidate_queue):
                            idx += 1
                            continue

                        if self.failover_enabled and attempt >= 1:
                            break

                        delay = 1.0
                        retry_after = e.response.headers.get("retry-after")
                        if retry_after:
                            with contextlib.suppress(ValueError):
                                delay = float(retry_after)
                        else:
                            m = re.search(r"try again in ([\d\.]+)s", resp_text, re.IGNORECASE)
                            if m:
                                delay = float(m.group(1))
                        await asyncio.sleep(min(max(delay, 0.01), 4.0))
                        break

                    else:
                        raise LLMClientError(
                            f"LLM API returned HTTP {status_code}: {resp_text}"
                        ) from e

                except httpx.RequestError as e:
                    last_error = e
                    if self.failover_enabled and attempt >= 1:
                        break
                    await asyncio.sleep(0.05 if self.failover_enabled else 0.5)
                    break

            if (
                self.failover_enabled
                and attempt >= 1
                and (status_code_for_failover or isinstance(last_error, httpx.RequestError))
            ):
                break

        # 3. Handle Secondary Provider Failover if enabled
        if self.failover_enabled and last_error is not None:
            # Privacy Guard: Strictly block cloud failover if primary is local
            if self.is_local and not self.is_secondary_local:
                raise PrivacyGuardBlockedError(
                    f"Privacy Guard: Blocked failover from local endpoint ({self.base_url}) to external cloud provider ({self.secondary_base_url}) to prevent data exfiltration."
                )

            if not self.has_secondary:
                raise LLMClientError(
                    f"Primary provider failed and secondary provider is not configured: {last_error}"
                )

            provider_label = (
                "OpenRouter"
                if "openrouter.ai" in self.secondary_base_url.lower()
                else self.secondary_base_url
            )
            reason_label = (
                f"Primary HTTP {status_code_for_failover} ({'Rate limit' if status_code_for_failover == 429 else 'Unavailable'})"
                if status_code_for_failover
                else f"Primary connection failure ({last_error})"
            )

            failover_ev = FailoverEvent(
                provider=provider_label,
                model=self.secondary_model,
                reason=reason_label,
                findings_handled=0,
            )
            self.failover_events.append(failover_ev)
            self.switched_models_log.append(
                f"Failover triggered: switching from '{self.base_url}' ({self.model}) to '{provider_label}' ({self.secondary_model}) due to {reason_label}"
            )
            self._secondary_active = True
            self.model = self.secondary_model

            try:
                res, usage = await self._execute_completion(
                    base_url=self.secondary_base_url,
                    api_key=self.secondary_api_key,
                    model=self.secondary_model,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    temperature=temperature,
                )
                failover_ev.findings_handled += findings_count
                return res, usage
            except Exception as e:
                raise LLMClientError(
                    f"Failover to secondary provider ({provider_label}) failed: {e}"
                ) from e

        # 4. If failover was not enabled or primary failed without failover
        if last_error:
            raise LLMClientError(f"LLM request failed after retries: {last_error}") from last_error

        raise LLMClientError("LLM request failed: no response received")
