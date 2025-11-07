import logging
from urllib.parse import urlparse
from typing import List

from . import register_module
from .base import BaseModule

logger = logging.getLogger(__name__)


@register_module("gau")
class GauModule(BaseModule):
    name = "gau"

    def _command_name(self) -> str:
        return "gau"

    def run(self, domain: str) -> List[str]:
        if not self.is_available():
            logger.warning("gau binary not available in PATH")
            return []

        out_lines = self._run_command(["gau", domain])
        hosts = []
        for line in out_lines:
            try:
                hostname = urlparse(line.strip()).hostname
            except ValueError:
                hostname = None
            if hostname:
                hosts.append(hostname)
        return self._dedupe(hosts, domain)
