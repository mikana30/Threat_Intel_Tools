import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional


logger = logging.getLogger(__name__)


@dataclass
class ModuleConfig:
    """Generic configuration for recon modules."""

    enabled: bool = True
    path: Optional[str] = None
    flags: List[str] = field(default_factory=list)
    timeout: int = 300  # seconds per invocation
    rate_limit_seconds: float = 0.0


class BaseModule:
    """Base class for recon enumeration modules."""

    name: str = "base"

    def __init__(self, config: ModuleConfig | None = None):
        self.config = config or ModuleConfig()

    def is_available(self) -> bool:
        """Return True if module prerequisites are met."""
        executable = self._command_name()
        if self.config.path:
            return Path(self.config.path).exists()
        if executable:
            return shutil.which(executable) is not None
        return False

    def run(self, domain: str) -> List[str]:
        """Execute the module for a domain and return subdomains."""
        raise NotImplementedError

    def _command_name(self) -> Optional[str]:
        """Return the CLI command associated with this module, if any."""
        return None

    # Helper methods -----------------------------------------------------
    def _run_command(self, cmd: List[str]) -> Iterable[str]:
        logger.debug("Running command: %s", " ".join(cmd))
        proc = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=self.config.timeout,
            check=False,
        )
        if proc.returncode != 0:
            logger.warning(
                "[%s] command exited with %s: %s",
                self.name,
                proc.returncode,
                proc.stderr.strip(),
            )
        return proc.stdout.splitlines()

    @staticmethod
    def _dedupe(domains: Iterable[str], target: str) -> List[str]:
        normalized = set()
        for line in domains:
            candidate = line.strip().lower()
            if not candidate or target not in candidate:
                continue
            normalized.add(candidate)
        return sorted(normalized)
