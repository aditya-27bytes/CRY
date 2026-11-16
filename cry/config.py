"""Configuration settings for CRY using an OpenAI-compatible LLM layer."""

import os
from pathlib import Path

from dotenv import load_dotenv

# Automatically load .env from project root or current working directory
load_dotenv(Path.cwd() / ".env")


class Settings:
    """Application settings, LLM provider endpoints, and scan controls."""

    # Generic OpenAI-compatible LLM Endpoint
    # Cloud default: Groq (https://api.groq.com/openai/v1)
    # Self-hosted private default: Ollama (http://localhost:11434/v1) or vLLM (http://localhost:8000/v1)
    LLM_BASE_URL: str = os.getenv("CRY_LLM_BASE_URL", "https://api.groq.com/openai/v1")
    LLM_API_KEY: str = os.getenv("CRY_LLM_API_KEY", os.getenv("GROQ_API_KEY", ""))
    LLM_MODEL: str = os.getenv("CRY_LLM_MODEL", os.getenv("GROQ_MODEL", "llama-3.1-8b-instant"))

    # Cost calculation rates per 1M tokens (Defaults for Llama 3.3 70B on hosted providers)
    COST_PER_MILLION_PROMPT_TOKENS: float = float(os.getenv("CRY_COST_PER_M_PROMPT", "0.59"))
    COST_PER_MILLION_COMPLETION_TOKENS: float = float(
        os.getenv("CRY_COST_PER_M_COMPLETION", "0.79")
    )

    # Scan Controls
    MAX_FILE_SIZE_MB: int = int(os.getenv("CRY_MAX_FILE_SIZE_MB", "5"))
    SCAN_TIMEOUT_SECONDS: int = int(os.getenv("CRY_SCAN_TIMEOUT_SECONDS", "300"))
    LOG_LEVEL: str = os.getenv("CRY_LOG_LEVEL", "INFO")

    # Configurable Fallback Models Pool (used when primary model hits rate limits or 404s)
    _env_fallbacks = os.getenv("CRY_LLM_FALLBACK_MODELS", "")
    FALLBACK_MODELS: list[str] = (
        [m.strip() for m in _env_fallbacks.split(",") if m.strip()]
        if _env_fallbacks
        else [
            "llama-3.1-8b-instant",
            "qwen/qwen3.8-27b",
            "openai/gpt-oss-20b",
            "openai/gpt-oss-120b",
            "llama-3.3-70b-versatile",
        ]
    )

    @classmethod
    def get_fallback_candidates(
        cls, base_url: str | None = None, current_model: str | None = None
    ) -> list[str]:
        """Return prioritized list of alternative models when primary model hits rate limits or is unavailable."""
        url = (base_url or cls.LLM_BASE_URL).lower()
        curr = current_model or cls.LLM_MODEL
        candidates: list[str] = []

        if cls.FALLBACK_MODELS:
            for m in cls.FALLBACK_MODELS:
                if m not in candidates:
                    candidates.append(m)

        # Provider specific defaults if not already present
        if "groq.com" in url:
            for m in [
                "llama-3.1-8b-instant",
                "qwen/qwen3.8-27b",
                "openai/gpt-oss-20b",
                "openai/gpt-oss-120b",
                "llama-3.3-70b-versatile",
            ]:
                if m not in candidates:
                    candidates.append(m)
        elif "openai.com" in url:
            for m in ["gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"]:
                if m not in candidates:
                    candidates.append(m)

        return [m for m in candidates if m != curr]

    @classmethod
    def override(
        cls,
        model: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
    ) -> None:
        """Dynamically override model, base_url, or API key for this execution."""
        if model:
            cls.LLM_MODEL = model
        if base_url:
            cls.LLM_BASE_URL = base_url.rstrip("/")
        if api_key is not None:
            cls.LLM_API_KEY = api_key

    @classmethod
    def is_local_llm(cls) -> bool:
        """Check if LLM is pointing to a local host (Ollama / vLLM / LocalAI)."""
        return "localhost" in cls.LLM_BASE_URL or "127.0.0.1" in cls.LLM_BASE_URL

    @classmethod
    def has_valid_llm_config(cls) -> bool:
        """Verify if we have an active API key or a local host endpoint."""
        if cls.is_local_llm():
            return True
        return bool(cls.LLM_API_KEY and not cls.LLM_API_KEY.startswith("your_"))


settings = Settings()
