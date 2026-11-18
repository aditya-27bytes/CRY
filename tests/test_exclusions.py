"""Tests for default exclusions (vendor, minified, gitignore, lockfiles) and --include-vendor flag."""

from pathlib import Path

from cry.exclusions import (
    ExclusionStats,
    GitIgnoreMatcher,
    is_minified_or_bundled,
    should_skip_path,
)
from cry.scanners.sast import scan_directory as scan_sast_dir
from cry.scanners.secrets import scan_directory as scan_secrets_dir

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VENDOR_APP_DIR = FIXTURES_DIR / "vendor_app"


def test_default_exclusions_skip_vendor_minified_and_gitignored() -> None:
    """Default scan must produce zero findings from vendor, minified, and gitignored files."""
    stats = ExclusionStats()
    sast_findings = scan_sast_dir(
        VENDOR_APP_DIR,
        include_vendor=False,
        stats=stats,
    )
    secret_findings = scan_secrets_dir(
        VENDOR_APP_DIR,
        include_vendor=False,
        stats=stats,
    )

    # By default, zero findings from vendor, minified, and gitignored files
    assert len(sast_findings) == 0
    assert len(secret_findings) == 0

    # Verify skipped stats
    assert stats.total_skipped >= 3
    counts = stats.counts
    assert "vendor" in counts
    assert "minified" in counts
    assert "gitignore" in counts

    summary = stats.format_summary()
    assert "files skipped" in summary
    assert "vendor:" in summary
    assert "minified:" in summary
    assert "gitignore:" in summary


def test_include_vendor_flag_detects_findings() -> None:
    """When include_vendor is True, findings inside vendor and minified files must be detected."""
    sast_findings = scan_sast_dir(
        VENDOR_APP_DIR,
        include_vendor=True,
    )
    secret_findings = scan_secrets_dir(
        VENDOR_APP_DIR,
        include_vendor=True,
    )

    all_findings = sast_findings + secret_findings

    # Findings must be present when exclusions are disabled
    assert len(all_findings) > 0
    flagged_files = {f.file_path for f in all_findings if f.file_path}
    assert any("vendor" in p for p in flagged_files)
    assert any("bundle.min.js" in p for p in flagged_files)


def test_content_minification_heuristics(tmp_path: Path) -> None:
    """Minified and bundled files must be identified by content heuristics even without minified names."""
    # 1. Normal clean file (multi-line, standard length)
    normal_file = tmp_path / "normal_script.js"
    normal_file.write_text(
        "function add(a, b) {\n    return a + b;\n}\nconsole.log(add(1, 2));\n",
        encoding="utf-8",
    )
    assert is_minified_or_bundled(normal_file) is False

    # 2. File with line length > 1000 characters
    long_line_file = tmp_path / "custom_library.js"
    long_line_file.write_text("var data = '" + "A" * 1200 + "';\n", encoding="utf-8")
    assert is_minified_or_bundled(long_line_file) is True

    # 3. File with .min.js in name
    named_min_file = tmp_path / "plugin.min.js"
    named_min_file.write_text("var x = 1;\n", encoding="utf-8")
    assert is_minified_or_bundled(named_min_file) is True


def test_gitignore_matcher(tmp_path: Path) -> None:
    """GitIgnoreMatcher must accurately filter files matching .gitignore patterns."""
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text(
        "# Comments\n\nbuild/\n*.log\n/secret.env\n!important.log\n",
        encoding="utf-8",
    )

    matcher = GitIgnoreMatcher(tmp_path)
    assert matcher.is_ignored(tmp_path / "build" / "app.js") is True
    assert matcher.is_ignored(tmp_path / "debug.log") is True
    assert matcher.is_ignored(tmp_path / "secret.env") is True
    assert matcher.is_ignored(tmp_path / "src" / "index.js") is False
    assert matcher.is_ignored(tmp_path / "important.log") is False


def test_should_skip_path_categories(tmp_path: Path) -> None:
    """should_skip_path must return exact reason codes for exclusions."""
    vendor_file = tmp_path / "vendor" / "module.js"
    vendor_file.parent.mkdir(parents=True, exist_ok=True)
    vendor_file.write_text("console.log(1);", encoding="utf-8")

    dec = should_skip_path(vendor_file, tmp_path, include_vendor=False)
    assert dec.skip is True
    assert dec.reason == "vendor"

    # With include_vendor=True, it should not skip
    dec_included = should_skip_path(vendor_file, tmp_path, include_vendor=True)
    assert dec_included.skip is False
