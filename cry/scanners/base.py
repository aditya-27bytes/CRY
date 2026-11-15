"""Base scanner abstraction for all CRY security scanner adapters."""

from abc import ABC, abstractmethod
from pathlib import Path

from cry.models import Finding


class BaseScanner(ABC):
    """Abstract interface for security scanners."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the scanner (e.g. 'gitleaks', 'semgrep', 'nuclei')."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Brief description of what this scanner checks."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if scanner binary or dependency is installed and available."""
        pass

    @abstractmethod
    async def scan(self, target: Path | str) -> list[Finding]:
        """Execute the scan against a local directory or remote URL.

        Args:
            target: Directory path (for SAST/Secrets) or URL string (for DAST).

        Returns:
            List of normalized Finding objects.
        """
        pass
