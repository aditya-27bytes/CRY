"""Canonical data schemas for CRY security findings, triage verdicts, and evaluation metrics."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

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
    confidence: float = Field(
        default=1.0,
        description="Confidence score (0.0 to 1.0) enriched by AST/taint and heuristic analysis",
    )
    taint_source: str | None = Field(
        default=None, description="Identified untrusted input source (e.g. req.query, argv)"
    )
    taint_sink: str | None = Field(
        default=None, description="Identified dangerous execution sink (e.g. cursor.execute, eval)"
    )


class TriagedFinding(BaseModel):
    """A finding evaluated and enriched by the LLM triage layer.

    IMPORTANT: Findings are NEVER silently discarded. Even likely false positives
    remain visible with clear explanation of the AI's reasoning.
    """

    finding: Finding
    status: TriageStatus = Field(
        default=TriageStatus.NEEDS_MANUAL_REVIEW, description="Triage status assigned by the model"
    )
    confidence: float = Field(
        default=1.0,
        description="Confidence score (0.0 to 1.0) assigned after context and LLM analysis",
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
    triaged_by_model: str | None = Field(
        default=None, description="Model identifier that triaged this finding"
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
    model_used: str | None = Field(
        default=None, description="Active AI model used for triage analysis"
    )
    model_switches: list[str] = Field(
        default_factory=list,
        description="Record of model failovers/switches due to rate limits or availability",
    )


class ModelBenchmarkScorecard(BaseModel):
    """Evaluation scorecard for an individual AI model against ground truth cases."""

    model_name: str
    provider_endpoint: str
    total_cases: int = 0
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    latency_seconds: float = 0.0
    actionable_patch_rate: float = 0.0
    token_usage: TokenUsage = Field(default_factory=TokenUsage)
    missed_case_ids: list[str] = Field(default_factory=list)
    wrongly_flagged_case_ids: list[str] = Field(default_factory=list)

    def compute_metrics(self) -> None:
        """Calculate Precision, Recall, and F1 score."""
        denom_p = self.true_positives + self.false_positives
        self.precision = (self.true_positives / denom_p) if denom_p > 0 else 0.0

        denom_r = self.true_positives + self.false_negatives
        self.recall = (self.true_positives / denom_r) if denom_r > 0 else 0.0

        if self.precision + self.recall > 0:
            self.f1_score = 2 * (self.precision * self.recall) / (self.precision + self.recall)
        else:
            self.f1_score = 0.0


class ModelComparisonLeaderboard(BaseModel):
    """Comparative benchmarking results for multiple models side-by-side."""

    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    scorecards: list[ModelBenchmarkScorecard] = Field(default_factory=list)

    def get_recommendation(self) -> dict[str, Any] | None:
        """Analyze scorecards and determine the optimal model recommendation."""
        if not self.scorecards:
            return None

        def rank_key(card: ModelBenchmarkScorecard) -> tuple[int, float, float, float]:
            return (
                -card.false_negatives,
                card.f1_score,
                -card.latency_seconds,
                -card.token_usage.estimated_cost_usd,
            )

        winner = max(self.scorecards, key=rank_key)
        fastest = min(self.scorecards, key=lambda c: c.latency_seconds)
        cheapest = min(self.scorecards, key=lambda c: c.token_usage.estimated_cost_usd)

        reasons = []
        if winner.false_negatives == 0:
            reasons.append("Zero False Negatives (100% security recall on ground truth)")
        else:
            reasons.append(f"Lowest False Negatives ({winner.false_negatives} missed)")

        reasons.append(f"F1 Accuracy Score: {winner.f1_score:.1%}")

        if winner.model_name == fastest.model_name:
            reasons.append(f"Fastest triage turnaround ({winner.latency_seconds:.2f}s)")
        else:
            reasons.append(f"Triage latency: {winner.latency_seconds:.2f}s")

        if winner.model_name == cheapest.model_name:
            reasons.append(f"Lowest token cost (${winner.token_usage.estimated_cost_usd:.4f})")

        return {
            "winner_model": winner.model_name,
            "f1_score": winner.f1_score,
            "latency": winner.latency_seconds,
            "cost": winner.token_usage.estimated_cost_usd,
            "reasons": reasons,
            "fastest_model": fastest.model_name,
            "cheapest_model": cheapest.model_name,
        }
