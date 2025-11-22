import logging
import re
from pathlib import Path
from typing import Iterable, List, Set

import requests

from . import register_module
from .base import BaseModule

logger = logging.getLogger(__name__)


def _parse_flag_int(flags: Iterable[str], key: str, default: int) -> int:
    prefix = f"--{key}="
    for flag in flags or []:
        if flag.startswith(prefix):
            try:
                return int(flag.split("=", 1)[1])
            except ValueError:
                return default
    return default


@register_module("subdomz")
class SubDomzModule(BaseModule):
    name = "subdomz"

    def __init__(self, config=None):
        super().__init__(config)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "ReconSubDomz/1.0"})
        timeout_cfg = self.config.timeout if self.config.timeout else 10
        self.http_timeout = min(10, max(3, timeout_cfg))
        self.max_results = _parse_flag_int(self.config.flags, "max-results", 250)

    def run(self, domain: str) -> List[str]:
        try:
            results = set()
            for source in (self._fetch_crt, self._fetch_bufferover, self._fetch_wayback):
                results.update(source(domain))
            if not results:
                return []
            return self._dedupe(sorted(results), domain)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("SubDomz python path failed: %s", exc)
            return self._fallback_script(domain)

    def _fallback_script(self, domain: str) -> List[str]:
        script_path = self.config.path or "./SubDomz.sh"
        if not Path(script_path).exists():
            logger.warning("SubDomz script not found at %s", script_path)
            return []
        cmd = ["bash", script_path, domain]
        return self._dedupe(self._run_command(cmd), domain)

    def _fetch_crt(self, domain: str) -> Set[str]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            resp = self.session.get(url, timeout=self.http_timeout)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            logger.debug("crt.sh lookup failed for %s", domain)
            return set()
        hosts: Set[str] = set()
        for entry in data[: self.max_results]:
            name_value = (entry or {}).get("name_value", "")
            for line in name_value.splitlines():
                line = line.replace("*.", "").strip().lower()
                if domain in line:
                    hosts.add(line)
        return hosts

    def _fetch_bufferover(self, domain: str) -> Set[str]:
        url = f"https://dns.bufferover.run/dns?q={domain}"
        try:
            resp = self.session.get(url, timeout=self.http_timeout)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            logger.debug("bufferover lookup failed for %s", domain)
            return set()
        hosts = set()
        for line in data.get("FDNS_A", [])[: self.max_results]:
            try:
                host = line.split(",", 1)[1].strip().lower()
            except (IndexError, AttributeError):
                continue
            if domain in host:
                hosts.add(host)
        return hosts

    def _fetch_wayback(self, domain: str) -> Set[str]:
        url = "https://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"*.{domain}/*",
            "output": "text",
            "fl": "original",
            "collapse": "urlkey",
            "limit": str(self.max_results),
        }
        try:
            resp = self.session.get(url, params=params, timeout=self.http_timeout)
            resp.raise_for_status()
            text = resp.text
        except Exception:
            logger.debug("wayback lookup failed for %s", domain)
            return set()
        hosts = set()
        pattern = re.compile(r"https?://([a-zA-Z0-9.-]+)\." + re.escape(domain))
        for line in text.splitlines():
            match = pattern.search(line)
            if match:
                hosts.add(f"{match.group(1).lower()}.{domain}")
        return hosts
