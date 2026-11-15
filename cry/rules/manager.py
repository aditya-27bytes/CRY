"""Rule Manager: coordinates embedded catalogs, workspace custom rules, and rule testing."""

from pathlib import Path
from typing import Any

from cry.models import Category
from cry.rules.models import RuleDefinition
from cry.rules.parser import parse_rule_file

CATALOG_DIR = Path(__file__).parent / "catalog"


class RuleManager:
    """Discovers, loads, and indexes security rules from embedded and custom sources."""

    def __init__(self, workspace_dir: Path | None = None, extra_dirs: list[Path] | None = None) -> None:
        self.workspace_dir = workspace_dir or Path.cwd()
        self.extra_dirs = extra_dirs or []
        self._rules: list[RuleDefinition] = []
        self.reload()

    def reload(self) -> None:
        """Reload all rules from embedded catalogs and workspace configuration files."""
        self._rules.clear()

        # 1. Embedded catalog
        if CATALOG_DIR.is_dir():
            for f in CATALOG_DIR.glob("*.toml"):
                self._rules.extend(parse_rule_file(f))
            for f in CATALOG_DIR.glob("*.json"):
                self._rules.extend(parse_rule_file(f))

        # 2. Workspace root rules (.cryrules.toml, .cryrules.json, .cryrules.yaml)
        ws_candidates = [
            self.workspace_dir / ".cryrules.toml",
            self.workspace_dir / ".cryrules.json",
            self.workspace_dir / ".cryrules.yaml",
            self.workspace_dir / ".cryrules.yml",
        ]
        for candidate in ws_candidates:
            if candidate.is_file():
                self._rules.extend(parse_rule_file(candidate))

        # 3. Extra directories
        for d in self.extra_dirs:
            if d.is_dir():
                for ext in ("*.toml", "*.json", "*.yaml", "*.yml"):
                    for f in d.glob(ext):
                        self._rules.extend(parse_rule_file(f))

    @property
    def all_rules(self) -> list[RuleDefinition]:
        """Return all active loaded rules."""
        return list(self._rules)

    def get_secret_rules(self) -> list[RuleDefinition]:
        """Return rules categorized under secret exposure."""
        return [r for r in self._rules if r.category == Category.SECRET_EXPOSURE]

    def get_sast_rules(self, extension: str | None = None) -> list[RuleDefinition]:
        """Return SAST vulnerability rules, optionally filtered by file extension."""
        sast = [r for r in self._rules if r.category != Category.SECRET_EXPOSURE]
        if not extension:
            return sast
        return [r for r in sast if r.applies_to_extension(extension)]

    def test_rules(self) -> dict[str, Any]:
        """Verify that all rules compile without regex errors or ReDoS traps."""
        results: dict[str, Any] = {
            "total_rules": len(self._rules),
            "valid_rules": 0,
            "failed_rules": [],
        }

        for rule in self._rules:
            try:
                patterns = rule.compile_patterns()
                if not patterns:
                    results["failed_rules"].append({"id": rule.rule_id, "error": "No patterns specified"})
                    continue

                # Run positive test samples if present
                for pos in rule.test_positive:
                    if not any(p.search(pos) for p in patterns):
                        results["failed_rules"].append(
                            {"id": rule.rule_id, "error": f"Failed positive test match: '{pos}'"}
                        )
                        break

                # Run negative test samples if present
                for neg in rule.test_negative:
                    if any(p.search(neg) for p in patterns):
                        results["failed_rules"].append(
                            {"id": rule.rule_id, "error": f"Failed negative test match (unwanted match): '{neg}'"}
                        )
                        break

                results["valid_rules"] += 1
            except Exception as e:
                results["failed_rules"].append({"id": rule.rule_id, "error": str(e)})

        return results
