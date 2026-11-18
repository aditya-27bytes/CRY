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
    """Lightweight .gitignore parser and pattern matcher."""

    def __init__(self, root_dir: Path) -> None:
        self.root_dir = root_dir
        self.rules: list[tuple[bool, str, bool]] = []
        self._load()

    def _load(self) -> None:
        gitignore_path = self.root_dir / ".gitignore"
        if not gitignore_path.is_file():
            return
        try:
            content = gitignore_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return

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
            if line.startswith("/"):
                line = line[1:]
            if line:
                self.rules.append((is_negated, line, dir_only))

    def is_ignored(self, path: Path) -> bool:
        if not self.rules:
            return False

        try:
            rel_path = path.relative_to(self.root_dir)
        except ValueError:
            rel_path = path

        rel_str = str(rel_path).replace("\\", "/")
        parts = rel_path.parts
        ignored = False

        for is_negated, pattern, _dir_only in self.rules:
            matched = False
            # If pattern has no slash, match filename or any directory component
            if "/" not in pattern:
                if any(fnmatch.fnmatch(part, pattern) for part in parts):
                    matched = True
            else:
                if (
                    fnmatch.fnmatch(rel_str, pattern)
                    or fnmatch.fnmatch(rel_str, f"*/{pattern}")
                    or fnmatch.fnmatch(rel_str, f"**/{pattern}")
                ):
                    matched = True

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
                "oversized",
                "cache_or_system",
            }:
                items.append(f"{reason}: {count}")
        breakdown = f" ({', '.join(items)})" if items else ""
        return f"{self.total_skipped} files skipped{breakdown}"
