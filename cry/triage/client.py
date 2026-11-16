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
from cry.models import TokenUsage


class LLMClientError(Exception):
    """Raised when the LLM provider fails to generate a response."""

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
    ) -> None:
        self.base_url = (base_url or settings.LLM_BASE_URL).rstrip("/")
        self.api_key = api_key if api_key is not None else settings.LLM_API_KEY
        self.model = model or settings.LLM_MODEL
        self.timeout = timeout if timeout != 15.0 else 60.0
        self.max_retries = max_retries
        self.switched_models_log: list[str] = []

        if fallback_models is not None:
            self.fallback_models = [m for m in fallback_models if m != self.model]
        else:
            self.fallback_models = settings.get_fallback_candidates(self.base_url, self.model)

    @property
    def is_configured(self) -> bool:
        """Check if client has a local endpoint or a non-empty API key."""
        if "localhost" in self.base_url or "127.0.0.1" in self.base_url:
            return True
        return bool(self.api_key and not self.api_key.startswith("your_"))

    @property
    def is_local(self) -> bool:
        """Check if client is pointing to a local offline endpoint."""
        return "localhost" in self.base_url or "127.0.0.1" in self.base_url

    async def _send_request(
        self, url: str, headers: dict[str, str], payload: dict[str, Any]
    ) -> httpx.Response:
        """Send HTTP POST request to LLM endpoint."""
        async with httpx.AsyncClient(timeout=httpx.Timeout(self.timeout, connect=5.0)) as client:
            return await client.post(url, headers=headers, json=payload)

    async def chat_completion_json(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        allow_model_switching: bool = True,
    ) -> tuple[dict[str, Any], TokenUsage]:
        """Request a structured JSON completion with multi-model failover upon rate limits.

        Args:
            system_prompt: Guiding instructions and schema definitions.
            user_prompt: Context and findings to analyze.
            temperature: Low temperature for deterministic security reasoning.
            allow_model_switching: Whether to dynamically fail over to alternative models upon 429/404.

        Returns:
            Tuple of (parsed_json_dict, TokenUsage).
        """
        if not self.is_configured:
            raise LLMClientError(
                "LLM provider is not configured. Set CRY_LLM_API_KEY in .env "
                "or point CRY_LLM_BASE_URL to http://localhost:11434/v1 for local Ollama."
            )

        headers: dict[str, str] = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        url = f"{self.base_url}/chat/completions"

        # Construct model candidate queue
        candidate_queue: list[str] = [self.model]
        if allow_model_switching:
            for fb in self.fallback_models:
                if fb not in candidate_queue:
                    candidate_queue.append(fb)

        data: dict[str, Any] | None = None
        last_error: Exception | None = None

        for attempt_round in range(self.max_retries + 1):
            idx = 0
            while idx < len(candidate_queue):
                target_model = candidate_queue[idx]
                payload: dict[str, Any] = {
                    "model": target_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": temperature,
                    "max_tokens": 4096,
                    "response_format": {"type": "json_object"},
                }

                try:
                    response = await self._send_request(url, headers=headers, payload=payload)
                    response.raise_for_status()

                    # If we used a fallback model, update active model and record failover
                    if target_model != self.model:
                        switch_info = (
                            f"Active model failed over from '{self.model}' to '{target_model}' "
                            f"due to API rate limit / availability"
                        )
                        if switch_info not in self.switched_models_log:
                            self.switched_models_log.append(switch_info)
                        self.model = target_model

                    data = response.json()
                    break

                except httpx.HTTPStatusError as e:
                    last_error = e
                    status_code = e.response.status_code
                    resp_text = e.response.text

                    if status_code == 401:
                        raise LLMClientError(
                            "Invalid or unauthorized API key (HTTP 401). "
                            "Please run 'cry configure' or check CRY_LLM_API_KEY in .env."
                        ) from e

                    elif status_code == 429:
                        # Rate limit reached (TPM / RPM)
                        retry_after_str = e.response.headers.get("retry-after")
                        delay = 2.0
                        if retry_after_str:
                            with contextlib.suppress(ValueError):
                                delay = float(retry_after_str)
                        else:
                            match = re.search(r"try again in ([\d\.]+)s", resp_text, re.IGNORECASE)
                            if match:
                                delay = float(match.group(1))

                        # Check if another fallback candidate exists in queue
                        has_alternative = allow_model_switching and (idx + 1 < len(candidate_queue))
                        if has_alternative:
                            next_model = candidate_queue[idx + 1]
                            failover_msg = (
                                f"Rate limit reached on '{target_model}' (HTTP 429). "
                                f"Switching to backup model '{next_model}'..."
                            )
                            if failover_msg not in self.switched_models_log:
                                self.switched_models_log.append(failover_msg)
                            idx += 1
                            continue

                        # All candidates throttled or single-model mode: wait before retrying next attempt round
                        if attempt_round < self.max_retries:
                            wait_time = min(max(delay, 1.5), 8.0)
                            await asyncio.sleep(wait_time)
                            break
                        else:
                            raise LLMClientError(
                                f"LLM API rate limit exceeded across available models: {resp_text}"
                            ) from e

                    elif status_code == 404:
                        # Model retired or not found: drop candidate and try next
                        candidate_queue.pop(idx)
                        if candidate_queue:
                            continue
                        raise LLMClientError(
                            f"Configured LLM model '{target_model}' was not found (HTTP 404): {resp_text}"
                        ) from e

                    elif status_code in (502, 503, 504):
                        # Transient server overload
                        if idx + 1 < len(candidate_queue) and allow_model_switching:
                            idx += 1
                            continue
                        if attempt_round < self.max_retries:
                            await asyncio.sleep(1.0)
                            break
                        raise LLMClientError(
                            f"LLM API server unavailable (HTTP {status_code}): {resp_text}"
                        ) from e

                    else:
                        raise LLMClientError(
                            f"LLM API returned HTTP {status_code}: {resp_text}"
                        ) from e

                except httpx.RequestError as e:
                    last_error = e
                    if attempt_round < self.max_retries:
                        await asyncio.sleep(1.0)
                        break
                    raise LLMClientError(f"Failed to connect to LLM at {url}: {e}") from e

            # Only break outer retry loop if request succeeded and data was assigned
            if data is not None:
                break
        else:
            if last_error:
                raise LLMClientError(
                    f"LLM request failed after retries and model failover: {last_error}"
                )
            raise LLMClientError("LLM request failed: unknown error")

        if data is None:
            if last_error:
                raise LLMClientError(
                    f"LLM request failed after retries and model failover: {last_error}"
                )
            raise LLMClientError("LLM request failed: no response received")

        # Extract content
        try:
            content_str = data["choices"][0]["message"]["content"]
            result_json = json.loads(content_str)
        except (KeyError, IndexError, json.JSONDecodeError) as e:
            raise LLMClientError(f"Invalid JSON response from LLM: {e}") from e

        # Extract usage telemetry
        usage_data = data.get("usage", {})
        prompt_tokens = usage_data.get("prompt_tokens", 0)
        completion_tokens = usage_data.get("completion_tokens", 0)
        total_tokens = usage_data.get("total_tokens", prompt_tokens + completion_tokens)

        # Estimate cost in USD
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
