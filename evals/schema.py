"""Data structures for accuracy evaluation and benchmark scoring."""

from pydantic import BaseModel, Field


class BenchmarkCase(BaseModel):
    """A single ground-truth test case used to evaluate accuracy."""

    case_id: str = Field(description="Unique identifier for the test case")
    name: str = Field(description="Short human-readable test case title")
    source: str = Field(description="Source benchmark (e.g., OWASP Juice Shop, DVWA, Synthetic)")
    file_path: str = Field(description="Path to the test file")
    is_vulnerability: bool = Field(
        description="True if this is a genuine security flaw, False if benign/trap"
    )
    expected_cwe: str | None = Field(
        default=None, description="Expected CWE ID if vulnerable (e.g. CWE-89)"
    )
    expected_severity: str | None = Field(
        default=None, description="Expected severity (CRITICAL, HIGH, etc.)"
    )


class BenchmarkScorecard(BaseModel):
    """Scorecard calculated by comparing CRY's triage verdict against ground truth."""

    total_cases: int = 0
    true_positives: int = 0  # Real vulnerability correctly caught as BLOCKER/WARNING
    false_positives: int = 0  # Safe code wrongly flagged as an active BLOCKER
    true_negatives: int = 0  # Safe code correctly identified or marked as LIKELY_FALSE_POSITIVE
    false_negatives: int = (
        0  # DANGEROUS: Real vulnerability missed by scanner or wrongly dismissed by AI
    )

    precision: float = (
        0.0  # TP / (TP + FP) -> Out of everything reported as real, how many were real?
    )
    recall: float = 0.0  # TP / (TP + FN) -> Out of all real vulnerabilities, how many did we catch?
    f1_score: float = 0.0  # Harmonic mean of precision & recall

    missed_case_ids: list[str] = Field(
        default_factory=list, description="IDs of real bugs that were missed"
    )
    wrongly_flagged_case_ids: list[str] = Field(
        default_factory=list, description="IDs of safe code flagged as bugs"
    )

    def compute_metrics(self) -> None:
        """Calculate precision, recall, and F1 score."""
        denom_precision = self.true_positives + self.false_positives
        self.precision = (self.true_positives / denom_precision) if denom_precision > 0 else 0.0

        denom_recall = self.true_positives + self.false_negatives
        self.recall = (self.true_positives / denom_recall) if denom_recall > 0 else 0.0

        if (self.precision + self.recall) > 0:
            self.f1_score = 2 * (self.precision * self.recall) / (self.precision + self.recall)
        else:
            self.f1_score = 0.0
