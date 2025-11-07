import logging
from typing import List

from . import register_module
from .base import BaseModule

logger = logging.getLogger(__name__)


@register_module("amass")
class AmassModule(BaseModule):
    name = "amass"

    def _command_name(self) -> str:
        return "amass"

    def run(self, domain: str) -> List[str]:
        if not self.is_available():
            logger.warning("amass binary not available in PATH")
            return []

        flags = self.config.flags or ["enum", "-passive"]
        cmd = ["amass", *flags, "-d", domain]
        return self._dedupe(self._run_command(cmd), domain)
