"""Pydantic models for declarative security rules."""

import re

from pydantic import BaseModel, Field

from cry.models import Category, Severity


class RuleDefinition(BaseModel):
    """Declarative definition of a security rule for SAST or Secrets scanning."""

    rule_id: str = Field(description="Unique rule identifier (e.g. gitleaks-supabase-key, sast-react-xss)")
    name: str = Field(description="Human readable name")
    category: Category = Field(default=Category.OTHER)
    severity: Severity = Field(default=Severity.HIGH)
    cwe_id: str | None = Field(default=None, description="CWE identifier (e.g. CWE-798, CWE-89)")
    languages: list[str] = Field(
        default_factory=lambda: [".py", ".js", ".ts", ".jsx", ".tsx"],
        description="Applicable file extensions. Empty or '*' means all files.",
    )
    patterns: list[str] = Field(
        default_factory=list,
        description="List of regex patterns. If any pattern matches, finding is triggered.",
    )
    entropy_min: float | None = Field(
        default=None,
        description="Minimum Shannon entropy threshold (for high-entropy secrets)",
    )
    description: str = Field(description="Problem explanation")
    fix_hint: str = Field(description="Guidance on how to remediate")
    suggested_fix: str | None = Field(default=None, description="Code replacement template")
    test_positive: list[str] = Field(
        default_factory=list,
        description="Test strings that MUST match this rule",
    )
    test_negative: list[str] = Field(
        default_factory=list,
        description="Test strings that MUST NOT match this rule",
    )

    def compile_patterns(self, flags: int = 0) -> list[re.Pattern[str]]:
        """Compile regex pattern strings into compiled regex objects."""
        compiled = []
        for p in self.patterns:
            compiled.append(re.compile(p, flags))
        return compiled

    def applies_to_extension(self, ext: str) -> bool:
        """Check if this rule applies to the specified file extension."""
        if not self.languages or "*" in self.languages:
            return True
        ext_lower = ext.lower() if ext.startswith(".") else f".{ext.lower()}"
        return ext_lower in [lang.lower() for lang in self.languages]
