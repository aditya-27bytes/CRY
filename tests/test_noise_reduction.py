"""Tests for Step 2 noise reduction: docs, examples, build configs, and test fixtures."""

from pathlib import Path

from cry.exclusions import (
    ExclusionStats,
    is_build_or_task_file,
    is_documentation_file,
    is_test_or_fixture_file,
)
from cry.models import Severity, Verdict
from cry.scanners.sast import scan_directory as scan_sast_dir
from cry.scanners.sast import scan_file as scan_sast_file
from cry.scanners.secrets import scan_directory as scan_secrets_dir
from cry.scanners.secrets import scan_file as scan_secrets_file
from cry.triage.client import LLMClient
from cry.triage.engine import TriageEngine


def test_path_classifiers() -> None:
    """Verify accurate classification of docs, build configs, and test fixtures."""
    # Documentation files
    assert is_documentation_file(Path("README.md")) is True
    assert is_documentation_file(Path("docs/architecture.markdown")) is True
    assert is_documentation_file(Path("CHANGELOG.md")) is True
    assert is_documentation_file(Path("src/app.py")) is False

    # Build and task runner configs
    assert is_build_or_task_file(Path("Gruntfile.js")) is True
    assert is_build_or_task_file(Path("gulpfile.js")) is True
    assert is_build_or_task_file(Path("webpack.config.js")) is True
    assert is_build_or_task_file(Path("src/routes/users.js")) is False

    # Test and fixture files
    assert is_test_or_fixture_file(Path("test/allocations-test.js")) is True
    assert is_test_or_fixture_file(Path("tests/test_api.py")) is True
    assert is_test_or_fixture_file(Path("spec/integration_spec.ts")) is True
    assert is_test_or_fixture_file(Path("fixtures/mock_data.json")) is True
    assert is_test_or_fixture_file(Path("app/routes/contributions.js")) is False


def test_readme_credential_example_never_blocks(tmp_path: Path) -> None:
    """Example database connection strings in README must never trigger a critical blocker."""
    readme = tmp_path / "README.md"
    readme.write_text(
        "# Project Setup\n\n"
        "Connect to local database using example string:\n"
        "```bash\n"
        "DATABASE_URL=mongodb://nodegoat:nodegoat_pass123@localhost:27017/nodegoat\n"
        "```\n",
        encoding="utf-8",
    )

    # 1. Directory scan by default skips documentation files from secrets
    stats = ExclusionStats()
    dir_findings = scan_secrets_dir(tmp_path, stats=stats, include_tests_and_docs=False)
    assert len(dir_findings) == 0
    assert stats.counts.get("docs") == 1

    # 2. Explicit direct file scan downgrades finding to LOW severity
    file_findings = scan_secrets_file(readme, tmp_path, include_tests_and_docs=False)
    assert len(file_findings) >= 1
    for f in file_findings:
        assert f.severity == Severity.LOW
        assert "[Doc/Example Credential]" in f.title

    # 3. Triage of documentation findings must be non-blocking
    engine = TriageEngine(client=LLMClient(api_key=""))
    report = engine._heuristic_fallback(file_findings, tmp_path)
    assert report.verdict != Verdict.DONT_SHIP
    assert len(report.blockers) == 0
    assert len(report.warnings) >= 1


def test_build_config_eval_downgraded_and_non_blocking(tmp_path: Path) -> None:
    """Build scripts (e.g., Gruntfile.js) using eval must be capped at LOW severity and non-blocking."""
    gruntfile = tmp_path / "Gruntfile.js"
    gruntfile.write_text(
        "module.exports = function(grunt) {\n"
        "    var config = eval(grunt.file.read('tasks.json'));\n"
        "    grunt.initConfig(config);\n"
        "};\n",
        encoding="utf-8",
    )

    findings = scan_sast_file(gruntfile, tmp_path, include_tests_and_docs=False)
    assert len(findings) >= 1
    for f in findings:
        assert f.severity == Severity.LOW
        assert "[Test/Build Fixture]" in f.title

    engine = TriageEngine(client=LLMClient(api_key=""))
    report = engine._heuristic_fallback(findings, tmp_path)
    assert report.verdict != Verdict.DONT_SHIP
    assert len(report.blockers) == 0


def test_nodegoat_real_world_simulation_filters_noise(tmp_path: Path) -> None:
    """Simulates OWASP NodeGoat scan: noisy README and Gruntfile must not block release."""
    # Setup mock NodeGoat structure
    (tmp_path / "app" / "routes").mkdir(parents=True)
    (tmp_path / "test").mkdir(parents=True)

    # Noisy files that previously caused false blockers
    readme = tmp_path / "README.md"
    readme.write_text(
        "Example MongoDB URL: mongodb://nodegoat:secret_db_pass@127.0.0.1:27017/nodegoat\n",
        encoding="utf-8",
    )

    gruntfile = tmp_path / "Gruntfile.js"
    gruntfile.write_text("eval(taskConfig);\n", encoding="utf-8")

    test_file = tmp_path / "test" / "allocations-test.js"
    test_file.write_text("eval(testMockInput);\n", encoding="utf-8")

    # Real critical vulnerability in production app
    real_vuln_file = tmp_path / "app" / "routes" / "contributions.js"
    real_vuln_file.write_text(
        "// Production route with critical code injection\n"
        "function handleContribution(req, res) {\n"
        "    var preTax = eval(req.body.preTax);\n"
        "    res.send(preTax);\n"
        "}\n",
        encoding="utf-8",
    )

    # Scan SAST and Secrets
    sast_findings = scan_sast_dir(tmp_path, include_tests_and_docs=False)
    secret_findings = scan_secrets_dir(tmp_path, include_tests_and_docs=False)
    all_findings = sast_findings + secret_findings

    # Triage
    engine = TriageEngine(client=LLMClient(api_key=""))
    report = engine._heuristic_fallback(all_findings, tmp_path)

    # CRITICAL VERIFICATION:
    # Exactly 1 blocker must be reported: the real eval in contributions.js!
    assert len(report.blockers) == 1
    blocker = report.blockers[0].finding
    assert "contributions.js" in str(blocker.file_path)
    assert blocker.severity == Severity.CRITICAL

    # The README, Gruntfile, and test/allocations-test.js must NEVER be in blockers
    blocker_files = {str(b.finding.file_path) for b in report.blockers}
    assert not any("README" in f for f in blocker_files)
    assert not any("Gruntfile" in f for f in blocker_files)
    assert not any("test" in f for f in blocker_files)

    # When --include-tests-and-docs is enabled, test and build findings are elevated
    sast_all = scan_sast_dir(tmp_path, include_tests_and_docs=True)
    secrets_all = scan_secrets_dir(tmp_path, include_tests_and_docs=True)
    report_all = engine._heuristic_fallback(
        sast_all + secrets_all, tmp_path, include_tests_and_docs=True
    )
    assert len(report_all.blockers) > 1
