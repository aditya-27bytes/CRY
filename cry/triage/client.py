"""OpenAI-compatible LLM client for CRY.

Supports any provider with an OpenAI-compatible endpoint:
- Groq Cloud: https://api.groq.com/openai/v1
- Local Ollama: http://localhost:11434/v1
- Local vLLM: http://localhost:8000/v1
- OpenAI: https://api.openai.com/v1

Uses standard httpx to make calls completely vendor-neutral without proprietary SDK lock-in.
"""

import json
from typing import Any

import httpx

from cry.config import settings
from cry.models import TokenUsage


class LLMClientError(Exception):
    """Raised when the LLM provider fails to generate a response."""

    pass


class LLMClient:
    """Lightweight, resilient OpenAI-compatible chat completion client."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        self.base_url = (base_url or settings.LLM_BASE_URL).rstrip("/")
        self.api_key = api_key if api_key is not None else settings.LLM_API_KEY
        self.model = model or settings.LLM_MODEL
        self.timeout = timeout if timeout != 15.0 else 60.0

    @property
    def is_configured(self) -> bool:
        """Check if client has a local endpoint or a non-empty API key."""
        if "localhost" in self.base_url or "127.0.0.1" in self.base_url:
            return True
        return bool(self.api_key and not self.api_key.startswith("your_"))

    async def chat_completion_json(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
    ) -> tuple[dict[str, Any], TokenUsage]:
        """Request a structured JSON completion from the LLM.

        Args:
            system_prompt: Guiding instructions and schema definitions.
            user_prompt: Context and findings to analyze.
            temperature: Low temperature for deterministic security reasoning.

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

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": 4096,
            "response_format": {"type": "json_object"},
        }

        url = f"{self.base_url}/chat/completions"

        async with httpx.AsyncClient(timeout=httpx.Timeout(self.timeout, connect=5.0)) as client:
            try:
                response = await client.post(url, headers=headers, json=payload)
                response.raise_for_status()
            except httpx.HTTPStatusError as e:
                # Automatic recovery if configured model is retired/not found
                if e.response.status_code == 404 and "model" in e.response.text.lower():
                    for fallback in ["openai/gpt-oss-120b", "qwen/qwen3.8-27b", "openai/gpt-oss-20b"]:
                        if fallback == self.model:
                            continue
                        payload["model"] = fallback
                        try:
                            fallback_resp = await client.post(url, headers=headers, json=payload)
                            fallback_resp.raise_for_status()
                            response = fallback_resp
                            self.model = fallback
                            break
                        except Exception:
                            continue
                    else:
                        raise LLMClientError(
                            f"LLM API returned HTTP {e.response.status_code}: {e.response.text}"
                        ) from e
                elif e.response.status_code == 429:
                    # If rate limit hit (e.g. 8000 TPM limit), fall back to secondary model
                    for fallback in ["qwen/qwen3.8-27b", "openai/gpt-oss-20b"]:
                        if fallback == self.model:
                            continue
                        payload["model"] = fallback
                        try:
                            fallback_resp = await client.post(url, headers=headers, json=payload)
                            fallback_resp.raise_for_status()
                            response = fallback_resp
                            self.model = fallback
                            break
                        except Exception:
                            continue
                    else:
                        raise LLMClientError(
                            f"LLM API returned HTTP {e.response.status_code}: {e.response.text}"
                        ) from e
                else:
                    raise LLMClientError(
                        f"LLM API returned HTTP {e.response.status_code}: {e.response.text}"
                    ) from e
            except httpx.RequestError as e:
                raise LLMClientError(f"Failed to connect to LLM at {url}: {e}") from e

        data = response.json()

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
