# AI Models & Provider Guide for CRY

> **Notice:** Model identifiers, availability, pricing, rate limits, and context windows change frequently over time across providers. Developers should verify current models, terms, and token pricing directly on their chosen provider's documentation before deployment.

---

## 🎯 Architecture & Philosophy

CRY is built with a **Scanner-First, Model-Agnostic** architecture:
1. **The Core Engine is Deterministic & Local**: SAST pattern scanning, AST taint tracking, network probes, and declarative TOML rules require zero tokens, zero network requests, and zero model dependencies.
2. **AI Triage is an Optional Advisory Layer**: You bring your own model (BYOM). CRY connects to any standard OpenAI-compatible API endpoint (`/chat/completions`) and does not hardcode required models.
3. **Privacy Guard**: If your primary endpoint points to a local address (`localhost`, `127.0.0.1`, `::1`, or private RFC-1918 subnets), CRY's built-in Privacy Guard blocks automatic failover to cloud providers, even if failover is enabled.

---

## ⚖️ Model Selection Trade-offs

When choosing an AI model for triage, consider these general trade-offs:

### 1. Privacy & Data Confidentiality
* **Local Offline Models (Ollama, vLLM, LM Studio, LocalAI)**:
  * **Pros**: 100% private. Source code and findings never leave your machine or private network. Works completely offline.
  * **Cons**: Requires local compute (sufficient GPU VRAM or system RAM). Slower on low-spec hardware.
* **Cloud API Providers (Groq, OpenRouter, OpenAI, etc.)**:
  * **Pros**: No local hardware requirements; fast cloud inference.
  * **Cons**: Requires network access and sending redacted code snippets to an external cloud API.

### 2. Speed vs. Depth of Reasoning
* **Fast / Smaller Parameter Models (e.g. 7B–14B class)**:
  * **Pros**: Rapid response times, lower token cost or low resource usage.
  * **Cons**: May produce simpler explanations or miss nuanced multi-hop exploit scenarios.
* **Larger / High-Capacity Models (e.g. 32B–70B+ class)**:
  * **Pros**: Deeper architectural threat modeling, higher code syntax comprehension, and nuanced vulnerability differentiation.
  * **Cons**: Higher inference latency and higher token costs on paid cloud endpoints.

### 3. Cost & Quota Management
* **Free Tiers & Hosted Routers**:
  * Cloud providers like Groq offer generous free-tier throughput but enforce strict Requests-Per-Minute (RPM) and Tokens-Per-Minute (TPM) limits.
  * Aggregator routers like OpenRouter offer unified credits and seamless access to hundreds of models, making them ideal as an optional secondary provider when primary quotas are reached.

---

## 🔄 Failover & Privacy Guard Configuration

CRY supports safe, opt-in failover to an optional secondary provider:

```ini
# Primary Provider (e.g., Groq or local Ollama)
CRY_LLM_BASE_URL=https://api.groq.com/openai/v1
CRY_LLM_API_KEY=gsk_...
CRY_LLM_MODEL=llama-3.1-8b-instant

# Optional Secondary Provider (e.g., OpenRouter)
CRY_SECONDARY_BASE_URL=https://openrouter.ai/api/v1
CRY_SECONDARY_API_KEY=sk-or-v1-...
CRY_SECONDARY_MODEL=meta-llama/llama-3.3-70b-instruct

# Failover Toggle (OPT-IN: defaults to off)
CRY_FAILOVER=on
```

### Privacy Guard Guarantee
If `CRY_LLM_BASE_URL` is set to a local endpoint (such as `http://localhost:11434/v1`):
* CRY will **never** send data or fail over to `CRY_SECONDARY_BASE_URL`.
* When local rate limits or resource exhaustion occur, CRY prints a visible notification and seamlessly falls back to its deterministic offline heuristic triage.
