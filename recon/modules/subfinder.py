import logging
from typing import List

from . import register_module
from .base import BaseModule

logger = logging.getLogger(__name__)


@register_module("subfinder")
class SubfinderModule(BaseModule):
    name = "subfinder"

    def _command_name(self) -> str:
        return "subfinder"

    def run(self, domain: str) -> List[str]:
        if not self.is_available():
            logger.warning("subfinder binary not available in PATH")
            return []

        flags = self.config.flags or ["-silent"]
        cmd = ["subfinder", "-d", domain, *flags]
        return self._dedupe(self._run_command(cmd), domain)
