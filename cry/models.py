"""Canonical data schemas for CRY security findings, triage verdicts, and evaluation metrics."""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Vulnerability severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(StrEnum):
    """Categorization of security findings."""

    SECRET_EXPOSURE = "SECRET_EXPOSURE"
    INJECTION = "INJECTION"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    INSECURE_DEPENDENCY = "INSECURE_DEPENDENCY"
    MISCONFIGURATION = "MISCONFIGURATION"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    OTHER = "OTHER"


class Verdict(StrEnum):
    """Final decision regarding deployment readiness."""

    SHIP = "SHIP"  # Safe to ship; no critical or high severity blockers
    FIX_FIRST = "FIX_FIRST"  # Warnings or medium issues present that should be fixed soon
    DONT_SHIP = "DONT_SHIP"  # Blocker: confirmed critical security flaw or active secret leak


class TriageStatus(StrEnum):
    """Triage categorization determined by the AI layer."""

    CONFIRMED_BLOCKER = "CONFIRMED_BLOCKER"  # True positive, high impact: must fix
    WARNING = "WARNING"  # Real issue, but lower severity/impact
    LIKELY_FALSE_POSITIVE = "LIKELY_FALSE_POSITIVE"  # Code appears safe/test-only, but kept visible
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"  # Ambiguous context; human eyes needed


class Finding(BaseModel):
    """A single normalized finding produced by any underlying scanner."""

    id: str = Field(description="Unique identifier for the finding")
    tool: str = Field(
        description="Name of scanner that detected the issue (e.g. gitleaks, semgrep)"
    )
    title: str = Field(description="Short human-readable title")
    description: str = Field(description="Detailed description of the issue")
    category: Category = Field(default=Category.OTHER)
    severity: Severity = Field(default=Severity.MEDIUM)
    file_path: str | None = Field(default=None, description="Relative path to affected file")
    line_start: int | None = Field(default=None, description="Starting line number")
    line_end: int | None = Field(default=None, description="Ending line number")
    code_snippet: str | None = Field(default=None, description="Snippet of offending code")
    cwe_id: str | None = Field(default=None, description="CWE identifier (e.g. CWE-89)")
    fix_hint: str | None = Field(default=None, description="Actionable instruction on how to fix")
    suggested_fix: str | None = Field(default=None, description="Exact replacement code or pattern")
    raw_evidence: str | None = Field(default=None, description="Raw tool output/payload")


class TriagedFinding(BaseModel):
    """A finding evaluated and enriched by the LLM triage layer.

    IMPORTANT: Findings are NEVER silently discarded. Even likely false positives
    remain visible with clear explanation of the AI's reasoning.
    """

    finding: Finding
    status: TriageStatus = Field(
        default=TriageStatus.NEEDS_MANUAL_REVIEW, description="Triage status assigned by the model"
    )
    exploitability_reasoning: str = Field(
        description="Detailed reasoning for why this is or isn't realistically exploitable"
    )
    plain_english_explanation: str = Field(
        description="Plain-English explanation for non-security founders"
    )
    fix_recommendation: str = Field(
        description="Clear, actionable instructions on how to fix the issue"
    )
    suggested_replacement_code: str | None = Field(
        default=None, description="Exact code diff or replacement snippet"
    )


class TokenUsage(BaseModel):
    """Telemetry for tracking LLM token consumption and costs per scan."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0


class VerdictReport(BaseModel):
    """The final executive report delivered to the developer."""

    verdict: Verdict = Field(description="The final Ship / Fix first / Don't ship decision")
    summary: str = Field(description="One-paragraph plain-English summary of security posture")
    target: str = Field(description="Repository path scanned")
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    total_raw_findings: int = 0

    # Transparent breakdown: Nothing is hidden
    blockers: list[TriagedFinding] = Field(default_factory=list, description="Critical/high issues")
    warnings: list[TriagedFinding] = Field(default_factory=list, description="Medium/low issues")
    likely_false_positives: list[TriagedFinding] = Field(
        default_factory=list,
        description="Items the AI believes are safe/test code, kept visible for transparency",
    )

    # Telemetry & Performance
    scan_duration_seconds: float = 0.0
    token_usage: TokenUsage = Field(default_factory=TokenUsage)
