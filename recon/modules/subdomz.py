import logging
from pathlib import Path
from typing import List

from . import register_module
from .base import BaseModule

logger = logging.getLogger(__name__)


@register_module("subdomz")
class SubDomzModule(BaseModule):
    name = "subdomz"

    def _command_name(self) -> str:
        return "bash"

    def run(self, domain: str) -> List[str]:
        script_path = self.config.path or "./SubDomz.sh"
        if not Path(script_path).exists():
            logger.warning("SubDomz script not found at %s", script_path)
            return []
        cmd = ["bash", script_path, domain]
        return self._dedupe(self._run_command(cmd), domain)
