"""Zero-dependency parser for declarative rules supporting TOML, JSON, and YAML formats."""

import json
import tomllib
from pathlib import Path
from typing import Any

from cry.rules.models import RuleDefinition


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    """Lightweight pure-Python parser for standard rule YAML structures."""
    try:
        import importlib

        yaml_mod = importlib.import_module("yaml")
        loaded: dict[str, Any] | None = yaml_mod.safe_load(text)
        return loaded or {}
    except Exception:
        pass

    # Basic fallback line parser for standard key: value / list structures
    result: dict[str, Any] = {"rules": []}
    lines = text.splitlines()
    current_rule: dict[str, Any] | None = None
    current_list_key: str | None = None

    for raw_line in lines:
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("- rule_id:") or stripped.startswith("- id:"):
            if current_rule:
                result["rules"].append(current_rule)
            key, val = stripped.lstrip("- ").split(":", 1)
            current_rule = {"rule_id": val.strip().strip("'\"")}
            current_list_key = None
            continue

        if current_rule is not None:
            if stripped.startswith("- "):
                val = stripped[2:].strip().strip("'\"")
                if current_list_key:
                    current_rule.setdefault(current_list_key, []).append(val)
                continue

            if ":" in stripped:
                k, v = stripped.split(":", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if not v:
                    current_list_key = k
                    current_rule[k] = []
                else:
                    current_list_key = None
                    if v.lower() == "true":
                        current_rule[k] = True
                    elif v.lower() == "false":
                        current_rule[k] = False
                    elif v.replace(".", "", 1).isdigit():
                        current_rule[k] = float(v) if "." in v else int(v)
                    else:
                        current_rule[k] = v

    if current_rule:
        result["rules"].append(current_rule)

    return result


def parse_rule_file(path: Path) -> list[RuleDefinition]:
    """Parse a single rule file (.toml, .json, .yaml, .yml) into RuleDefinition objects."""
    if not path.is_file():
        return []

    ext = path.suffix.lower()
    raw_rules: list[dict[str, Any]] = []

    try:
        content = path.read_text(encoding="utf-8")
        if ext == ".toml":
            data = tomllib.loads(content)
            raw_rules = data.get("rules", [])
        elif ext == ".json":
            data = json.loads(content)
            raw_rules = data.get("rules", data) if isinstance(data, dict) else data
        elif ext in {".yaml", ".yml"}:
            data = _parse_simple_yaml(content)
            raw_rules = data.get("rules", [])
        else:
            return []
    except Exception:
        return []

    rules: list[RuleDefinition] = []
    for item in raw_rules:
        if not isinstance(item, dict):
            continue
        try:
            # Normalize field names if synonyms used
            if "id" in item and "rule_id" not in item:
                item["rule_id"] = item["id"]
            if "pattern" in item and "patterns" not in item:
                item["patterns"] = [item["pattern"]]
            rule = RuleDefinition(**item)
            rules.append(rule)
        except Exception:
            continue

    return rules
