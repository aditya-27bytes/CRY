"""Unit tests for the declarative security rules engine (Phase 2)."""

import json
import tempfile
from pathlib import Path

from cry.models import Category, Severity
from cry.rules.manager import RuleManager
from cry.rules.models import RuleDefinition
from cry.rules.parser import parse_rule_file


def test_rule_definition_compilation() -> None:
    """RuleDefinition compiles valid regex patterns and matches correctly."""
    rule = RuleDefinition(
        rule_id="test-rule-01",
        name="Test API Token",
        category=Category.SECRET_EXPOSURE,
        severity=Severity.HIGH,
        cwe_id="CWE-798",
        languages=[".py", ".ts"],
        patterns=[r"test_token_[0-9a-f]{16}"],
        description="Test secret token pattern",
        fix_hint="Use environment variable",
        test_positive=["const x = 'test_token_0123456789abcdef';"],
        test_negative=["const x = 'regular_string';"],
    )

    compiled = rule.compile_patterns()
    assert len(compiled) == 1
    assert compiled[0].search("test_token_0123456789abcdef") is not None
    assert compiled[0].search("regular_string") is None
    assert rule.applies_to_extension(".py") is True
    assert rule.applies_to_extension(".ts") is True
    assert rule.applies_to_extension(".go") is False


def test_catalog_rules_loaded() -> None:
    """Embedded rules catalog loads both secret and SAST rules successfully."""
    mgr = RuleManager()
    all_rules = mgr.all_rules
    assert len(all_rules) >= 15

    secret_rules = mgr.get_secret_rules()
    assert len(secret_rules) >= 9
    assert any("supabase" in r.rule_id.lower() for r in secret_rules)
    assert any("github" in r.rule_id.lower() for r in secret_rules)

    sast_rules = mgr.get_sast_rules(".ts")
    assert len(sast_rules) >= 5
    assert any("xss" in r.rule_id.lower() or "prototype" in r.rule_id.lower() for r in sast_rules)


def test_custom_rule_file_parsing() -> None:
    """Parser handles custom TOML, JSON, and YAML rule formats."""
    with tempfile.TemporaryDirectory() as td:
        t_path = Path(td)

        # 1. Test TOML parsing
        toml_file = t_path / "custom.toml"
        toml_file.write_text(
            """
[[rules]]
rule_id = "custom-auth-bypass"
name = "Custom Auth Bypass Header"
category = "AUTHENTICATION"
severity = "CRITICAL"
cwe_id = "CWE-287"
languages = [".py"]
patterns = ['X-Admin-Bypass:\\s*true']
description = "Dangerous backdoor header detected."
fix_hint = "Remove debug header."
""",
            encoding="utf-8",
        )
        rules = parse_rule_file(toml_file)
        assert len(rules) == 1
        assert rules[0].rule_id == "custom-auth-bypass"
        assert rules[0].severity == Severity.CRITICAL

        # 2. Test JSON parsing
        json_file = t_path / "custom.json"
        json_payload = {
            "rules": [
                {
                    "id": "custom-crypto-salt",
                    "name": "Hardcoded Crypto Salt",
                    "category": "MISCONFIGURATION",
                    "severity": "HIGH",
                    "cwe_id": "CWE-326",
                    "languages": [".ts"],
                    "patterns": [r"const\s+SALT\s*=\s*['\"][^'\"]+['\"]"],
                    "description": "Hardcoded cryptographic salt.",
                    "fix_hint": "Generate random salt.",
                }
            ]
        }
        json_file.write_text(json.dumps(json_payload), encoding="utf-8")
        json_rules = parse_rule_file(json_file)
        assert len(json_rules) == 1
        assert json_rules[0].rule_id == "custom-crypto-salt"


def test_rules_manager_validation() -> None:
    """RuleManager test_rules passes with zero failed rules."""
    mgr = RuleManager()
    results = mgr.test_rules()
    assert results["total_rules"] >= 15
    assert results["valid_rules"] == results["total_rules"]
    assert len(results["failed_rules"]) == 0


def test_bare_cry_rules_cli_command() -> None:
    """Bare 'cry rules' lists catalog directly without requiring 'list' subcommand."""
    from typer.testing import CliRunner

    from cry.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "Declarative Security Rules Catalog" in result.output
    assert "active rules" in result.output
