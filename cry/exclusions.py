"""Centralized path, vendor, minified, and gitignore exclusions for CRY scanners."""

import fnmatch
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# Directories always skipped regardless of include_vendor (internal/cache/system)
ALWAYS_SKIP_DIRS: set[str] = {
    ".git",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".tox",
    ".egg-info",
}

# Directories skipped by default (vendor, build artifacts, coverage)
DEFAULT_EXCLUDED_DIRS: set[str] = {
    "node_modules",
    "vendor",
    "vendors",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "coverage",
}

# Standard lockfile names to skip for SAST/Secrets (SCA still reads manifests)
LOCKFILE_NAMES: set[str] = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pipfile.lock",
    "composer.lock",
    "cargo.lock",
    "gemfile.lock",
    "mix.lock",
}

# Filename suffixes indicating minified or bundled assets
MINIFIED_OR_BUNDLED_SUFFIXES: tuple[str, ...] = (
    ".min.js",
    ".min.css",
    ".min.map",
    ".bundle.js",
    ".bundle.css",
    ".chunk.js",
    ".chunk.css",
    ".map",
)

BUNDLED_EXACT_NAMES: set[str] = {
    "bundle.js",
    "bundle.css",
    "vendor.js",
    "vendors.js",
    "vendor-bundle.js",
}

# Documentation file detection
DOC_EXTENSIONS: set[str] = {".md", ".markdown", ".rst", ".txt", ".adoc", ".asciidoc"}
DOC_DIR_NAMES: set[str] = {"docs", "doc", "documentation", "guides", "manual"}
DOC_EXACT_NAMES: set[str] = {
    "readme",
    "readme.md",
    "readme.markdown",
    "readme.txt",
    "readme.rst",
    "changelog",
    "changelog.md",
    "contributing",
    "contributing.md",
    "license",
    "license.md",
    "security",
    "security.md",
    "benchmark.md",
}

# Build and task runner config files
BUILD_CONFIG_PATTERNS: tuple[str, ...] = (
    "gruntfile",
    "gulpfile",
    "webpack",
    "vite.config",
    "rollup.config",
    "esbuild",
    "babel.config",
    "karma.conf",
    "jest.config",
    "tsconfig",
    "next.config",
    "nuxt.config",
    "postcss.config",
    "tailwind.config",
)

# Test, mock, fixture directories and suffixes
TEST_DIR_NAMES: set[str] = {
    "test",
    "tests",
    "__tests__",
    "spec",
    "specs",
    "fixtures",
    "e2e",
    "mock",
    "mocks",
    "test_fixtures",
    "eval",
    "evals",
    "dataset",
    "datasets",
}
TEST_FILE_PREFIXES: tuple[str, ...] = ("test_", "mock_", "spec_")
TEST_FILE_SUFFIXES: tuple[str, ...] = (
    "_test.py",
    "_spec.rb",
    "_test.go",
    "_test.rs",
    "tests.rs",
    ".test.ts",
    ".spec.ts",
    ".test.js",
    ".spec.js",
    ".test.tsx",
    ".spec.tsx",
    ".test.jsx",
    ".spec.jsx",
    ".test.mjs",
    ".test.cjs",
    ".mock.ts",
    ".mock.js",
    "-test.js",
    "-spec.js",
)
TEST_FILE_EXACT: set[str] = {
    "test.py",
    "test.js",
    "test.ts",
    "tests.py",
    "tests.js",
    "tests.ts",
    "conftest.py",
}


def is_documentation_file(file_path: Path | str) -> bool:
    """Return True if the file is documentation or a markdown/readme file."""
    p = Path(file_path) if isinstance(file_path, str) else file_path
    name_lower = p.name.lower()
    stem_lower = p.stem.lower()
    suffix = p.suffix.lower()

    if name_lower in DOC_EXACT_NAMES or stem_lower in (
        "readme",
        "changelog",
        "contributing",
        "license",
    ):
        return True
    if suffix in DOC_EXTENSIONS:
        return True
    parts = {part.lower() for part in p.parts}
    return not parts.isdisjoint(DOC_DIR_NAMES)


def is_build_or_task_file(file_path: Path | str) -> bool:
    """Return True if the file is a build configuration or task runner script."""
    p = Path(file_path) if isinstance(file_path, str) else file_path
    name_lower = p.name.lower()
    return any(pat in name_lower for pat in BUILD_CONFIG_PATTERNS)


def is_test_or_fixture_file(file_path: Path | str, base_dir: Path | None = None) -> bool:
    """Check if file lives under a test, mock, fixture directory or matches test naming."""
    p = Path(file_path) if isinstance(file_path, str) else file_path
    name_lower = p.name.lower()

    if name_lower in TEST_FILE_EXACT:
        return True
    if name_lower.startswith(TEST_FILE_PREFIXES):
        return True
    if name_lower.endswith(TEST_FILE_SUFFIXES):
        return True

    if base_dir:
        try:
            rel = p.relative_to(base_dir)
            parts = {part.lower() for part in rel.parts}
        except ValueError:
            parts = {part.lower() for part in p.parts}
    else:
        parts = {part.lower() for part in p.parts}

    return not parts.isdisjoint(TEST_DIR_NAMES)


def is_minified_or_bundled(file_path: Path, max_check_bytes: int = 65536) -> bool:
    """Detect whether a file is minified or bundled by filename or content heuristics."""
    name_lower = file_path.name.lower()

    # 1. By name or extension
    if name_lower in BUNDLED_EXACT_NAMES:
        return True
    if name_lower.endswith(MINIFIED_OR_BUNDLED_SUFFIXES):
        return True
    if ".min." in name_lower:
        return True

    # 2. Only inspect text/source files for content heuristics
    ext = file_path.suffix.lower()
    if ext not in {".js", ".jsx", ".ts", ".tsx", ".css", ".html", ".htm", ".mjs", ".cjs"}:
        return False

    # 3. By content heuristic (check line lengths on first 64KB)
    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            chunk = f.read(max_check_bytes)
    except OSError:
        return False

    if not chunk:
        return False

    lines = chunk.splitlines()
    if not lines:
        return False

    # Check for extremely long single line (normal source code rarely exceeds 1000 chars)
    max_len = max(len(line) for line in lines)
    if max_len > 1000:
        return True

    # Check for single-line files with > 500 characters
    if len(lines) == 1 and len(lines[0]) > 500:
        return True

    # Check for high average line length on multi-line files
    non_empty = [line for line in lines if line.strip()]
    if len(non_empty) >= 2:
        avg_len = sum(len(line) for line in non_empty) / len(non_empty)
        if avg_len > 200:
            return True

    # Check for sourceMappingURL marker combined with long line (> 300)
    return ("//# sourceMappingURL=" in chunk or "/*# sourceMappingURL=" in chunk) and max_len > 300


class GitIgnoreMatcher:
    """Lightweight .gitignore and .cryignore parser and pattern matcher."""

    def __init__(self, root_dir: Path) -> None:
        self.root_dir = root_dir.resolve()
        # Stores tuples of (is_negated, pattern, dir_only, anchored, base_dir)
        self.rules: list[tuple[bool, str, bool, bool, Path]] = []
        self._load()

    def _parse_file(self, ignore_path: Path) -> None:
        try:
            content = ignore_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return

        base_dir = ignore_path.parent
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            is_negated = line.startswith("!")
            if is_negated:
                line = line[1:].strip()
            dir_only = line.endswith("/")
            if dir_only:
                line = line[:-1]
            anchored = line.startswith("/")
            if anchored:
                line = line[1:]
            if line:
                self.rules.append((is_negated, line, dir_only, anchored, base_dir))

    def _load(self) -> None:
        # Check parent hierarchy up to git root or filesystem root to inherit repository ignore rules
        curr = self.root_dir
        chain = [curr]
        while curr.parent != curr:
            curr = curr.parent
            chain.append(curr)
            if (curr / ".git").exists():
                break

        # Load rules from top-most parent down to root_dir
        for d in reversed(chain):
            for name in (".gitignore", ".cryignore"):
                ignore_file = d / name
                if ignore_file.is_file():
                    self._parse_file(ignore_file)

    def is_ignored(self, path: Path) -> bool:
        if not self.rules:
            return False

        p_res = path.resolve()
        ignored = False

        for is_negated, pattern, _dir_only, anchored, base_dir in self.rules:
            try:
                rel_path = p_res.relative_to(base_dir)
            except ValueError:
                continue

            rel_str = str(rel_path).replace("\\", "/")
            parts = rel_path.parts

            matched = False
            if anchored:
                matched = (
                    fnmatch.fnmatch(rel_str, pattern)
                    or rel_str.startswith(f"{pattern}/")
                    or fnmatch.fnmatch(rel_str, f"{pattern}/*")
                    or fnmatch.fnmatch(rel_str, f"{pattern}/**")
                )
            elif "/" not in pattern:
                matched = any(fnmatch.fnmatch(part, pattern) for part in parts)
            else:
                matched = (
                    fnmatch.fnmatch(rel_str, pattern)
                    or rel_str.startswith(f"{pattern}/")
                    or fnmatch.fnmatch(rel_str, f"*/{pattern}")
                    or fnmatch.fnmatch(rel_str, f"*/{pattern}/*")
                    or fnmatch.fnmatch(rel_str, f"*/{pattern}/**")
                    or fnmatch.fnmatch(rel_str, f"**/{pattern}/*")
                )

            if matched:
                ignored = not is_negated

        return ignored


@dataclass
class SkipDecision:
    skip: bool
    reason: str | None = None


def should_skip_path(
    file_path: Path,
    base_dir: Path,
    include_vendor: bool = False,
    gitignore: GitIgnoreMatcher | None = None,
    max_file_size_mb: int = 5,
) -> SkipDecision:
    """Check if file should be skipped by scanners, returning the decision and reason."""
    parts = {p.lower() for p in file_path.parts}
    name_lower = file_path.name.lower()

    # 1. Always skip system/cache dirs
    if parts & ALWAYS_SKIP_DIRS:
        return SkipDecision(True, "cache_or_system")

    # 2. Skip oversized files
    try:
        if file_path.is_file() and file_path.stat().st_size > max_file_size_mb * 1024 * 1024:
            return SkipDecision(True, "oversized")
    except OSError:
        return SkipDecision(True, "unreadable")

    # If include_vendor is True, do not skip vendor, minified, bundled, lockfile, or gitignored files
    if include_vendor:
        return SkipDecision(False)

    # 3. Skip vendor / build dirs
    matched_excluded = parts & DEFAULT_EXCLUDED_DIRS
    if matched_excluded:
        if matched_excluded & {"vendor", "vendors", "node_modules"}:
            return SkipDecision(True, "vendor")
        return SkipDecision(True, "build_artifact")

    # 4. Skip lockfiles
    if name_lower in LOCKFILE_NAMES:
        return SkipDecision(True, "lockfile")

    # 5. Skip minified / bundled by name or content
    if is_minified_or_bundled(file_path):
        if (
            name_lower.endswith((".bundle.js", ".chunk.js"))
            or name_lower in BUNDLED_EXACT_NAMES
            or name_lower.endswith(".map")
        ):
            return SkipDecision(True, "bundled")
        return SkipDecision(True, "minified")

    # 6. Skip gitignored files
    if gitignore and gitignore.is_ignored(file_path):
        return SkipDecision(True, "gitignore")

    return SkipDecision(False)


@dataclass
class ExclusionStats:
    """Tracks how many files were skipped during a scan and why."""

    skipped_files: dict[Path, str] = field(default_factory=dict)

    def record_skip(self, path: Path, reason: str) -> None:
        if path not in self.skipped_files and reason != "cache_or_system":
            self.skipped_files[path] = reason

    @property
    def total_skipped(self) -> int:
        return len(self.skipped_files)

    @property
    def counts(self) -> dict[str, int]:
        c: dict[str, int] = defaultdict(int)
        for reason in self.skipped_files.values():
            c[reason] += 1
        return dict(c)

    def format_summary(self) -> str:
        if not self.skipped_files:
            return "0 files skipped"
        counts = self.counts
        items = []
        for reason in [
            "vendor",
            "minified",
            "bundled",
            "build_artifact",
            "lockfile",
            "gitignore",
            "docs",
            "test_or_fixture",
            "build_config",
            "oversized",
        ]:
            if counts.get(reason, 0) > 0:
                items.append(f"{reason}: {counts[reason]}")
        for reason, count in sorted(counts.items()):
            if reason not in {
                "vendor",
                "minified",
                "bundled",
                "build_artifact",
                "lockfile",
                "gitignore",
                "docs",
                "test_or_fixture",
                "build_config",
                "oversized",
                "cache_or_system",
            }:
                items.append(f"{reason}: {count}")
        breakdown = f" ({', '.join(items)})" if items else ""
        return f"{self.total_skipped} files skipped{breakdown}"
