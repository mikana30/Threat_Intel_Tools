import logging
from typing import List

from . import register_module
from .base import BaseModule

logger = logging.getLogger(__name__)


@register_module("assetfinder")
class AssetfinderModule(BaseModule):
    name = "assetfinder"

    def _command_name(self) -> str:
        return "assetfinder"

    def run(self, domain: str) -> List[str]:
        if not self.is_available():
            logger.warning("assetfinder binary not available in PATH")
            return []

        flags = self.config.flags or ["--subs-only"]
        cmd = ["assetfinder", *flags, domain]
        return self._dedupe(self._run_command(cmd), domain)
