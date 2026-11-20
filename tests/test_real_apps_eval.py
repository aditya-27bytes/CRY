"""Unit tests for the real-application benchmark harness and manifest."""

import tempfile
from pathlib import Path
from typing import Any

from evals.real_apps.runner import (
    MANIFEST_PATH,
    evaluate_real_app,
    load_real_apps_manifest,
)


def test_manifest_schema_and_validity() -> None:
    """Ensure manifest.json is well-formed and specifies required benchmark target fields."""
    manifest = load_real_apps_manifest(MANIFEST_PATH)
    assert manifest["benchmark_suite"] == "real_apps"
    assert manifest["version"] == "0.4.1"
    assert len(manifest["targets"]) >= 1

    nodegoat = next(t for t in manifest["targets"] if t["name"] == "OWASP NodeGoat")
    assert nodegoat["pinned_commit"]
    assert nodegoat["repo_url"] == "https://github.com/OWASP/NodeGoat.git"
    assert nodegoat["expected_totals"]["blockers"] == 7
    assert nodegoat["expected_totals"]["warnings"] == 4
    assert len(nodegoat["expected_blocker_files"]) >= 4
    assert len(nodegoat["expected_warning_files"]) >= 4
    assert "README.md" in nodegoat["expected_clean_files"]


def test_evaluate_real_app_mock_repo_matching_expectations(tmp_path: Path) -> None:
    """Ensure evaluate_real_app reports passed=True when all expectations match."""
    # Create mock target files
    cert_dir = tmp_path / "artifacts" / "cert"
    cert_dir.mkdir(parents=True)
    (cert_dir / "server.key").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n", encoding="utf-8"
    )

    dao_dir = tmp_path / "app" / "data"
    dao_dir.mkdir(parents=True)
    (dao_dir / "allocations-dao.js").write_text(
        "allocations.find({ $where: 'this.userId == ' + uid });\n", encoding="utf-8"
    )

    routes_dir = tmp_path / "app" / "routes"
    routes_dir.mkdir(parents=True)
    (routes_dir / "contributions.js").write_text(
        "const a = eval(req.body.a);\nconst b = eval(req.body.b);\nconst c = eval(req.body.c);\n",
        encoding="utf-8",
    )
    (routes_dir / "research.js").write_text(
        "const url = req.query.url;\nreturn needle.get(url, cb);\n", encoding="utf-8"
    )
    (routes_dir / "index.js").write_text("return res.redirect(req.query.url);\n", encoding="utf-8")

    # Clean file
    (tmp_path / "README.md").write_text(
        "# Mock Project\nSafe documentation text.\n", encoding="utf-8"
    )

    empty_checks: list[dict[str, Any]] = []
    mock_target_config: dict[str, Any] = {
        "name": "Mock App",
        "pinned_commit": "mock123",
        "expected_totals": {"blockers": 6, "warnings": 1},
        "expected_blocker_files": [
            "artifacts/cert/server.key",
            "app/data/allocations-dao.js",
            "app/routes/contributions.js",
            "app/routes/research.js",
        ],
        "expected_warning_files": ["app/routes/index.js"],
        "expected_clean_files": ["README.md"],
        "finding_checks": empty_checks,
    }

    result = evaluate_real_app(mock_target_config, tmp_path)
    assert result["passed"] is True
    assert len(result["diffs"]) == 0
    assert result["actual_totals"]["blockers"] == 6
    assert result["actual_totals"]["warnings"] == 1


def test_evaluate_real_app_detects_diffs_when_expectations_violated(tmp_path: Path) -> None:
    """Ensure evaluate_real_app detects missing blockers, unexpected warnings, and clean file violations."""
    # Target only contains a clean file, missing expected blockers
    (tmp_path / "README.md").write_text(
        "mongodb://user:pass@localhost:27017/db\n", encoding="utf-8"
    )

    empty_warnings: list[str] = []
    mock_target_config: dict[str, Any] = {
        "name": "Violating App",
        "pinned_commit": "mock456",
        "expected_totals": {"blockers": 2, "warnings": 0},
        "expected_blocker_files": ["app/data/allocations-dao.js"],
        "expected_warning_files": empty_warnings,
        "expected_clean_files": ["README.md"],
    }

    result = evaluate_real_app(mock_target_config, tmp_path)
    assert result["passed"] is False
    assert len(result["diffs"]) > 0
    assert any("MISSING BLOCKER FILE" in d for d in result["diffs"])


def test_real_apps_runner_end_to_end_on_cached_nodegoat() -> None:
    """If OWASP NodeGoat is cached locally, verify end-to-end evaluation matches manifest perfectly."""
    nodegoat_temp = Path(tempfile.gettempdir()) / "nodegoat"
    if not (nodegoat_temp / ".git").is_dir():
        return

    manifest = load_real_apps_manifest()
    nodegoat_target = next(t for t in manifest["targets"] if t["name"] == "OWASP NodeGoat")

    result = evaluate_real_app(nodegoat_target, nodegoat_temp)
    assert result["passed"] is True
    assert result["actual_totals"]["blockers"] == 7
    assert result["actual_totals"]["warnings"] == 4
    assert len(result["diffs"]) == 0
