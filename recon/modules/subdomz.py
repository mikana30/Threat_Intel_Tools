import logging
import re
import time
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
        # Increase timeout to 30 seconds for better resilience with slow APIs like crt.sh
        timeout_cfg = self.config.timeout if self.config.timeout else 30
        self.http_timeout = min(30, max(3, timeout_cfg))
        self.max_results = _parse_flag_int(self.config.flags, "max-results", 250)
        self.max_retries = 3  # Number of retry attempts per API
        self.retry_backoff = 2.0  # Exponential backoff multiplier

    def run(self, domain: str) -> List[str]:
        try:
            results = set()
            api_sources = (
                ("crt.sh", self._fetch_crt),
                ("BufferOver", self._fetch_bufferover),
                ("Wayback", self._fetch_wayback),
            )

            # Track API success/failure for better visibility
            successful_apis = []
            failed_apis = []

            for source_name, source_func in api_sources:
                # Use retry logic for each API
                source_results = self._retry_with_backoff(source_func, domain, source_name)

                if source_results:
                    results.update(source_results)
                    successful_apis.append(source_name)
                    logger.info("%s API returned %d subdomains for %s",
                               source_name, len(source_results), domain)
                else:
                    failed_apis.append(source_name)
                    logger.warning("%s API returned 0 results for %s (after %d retries)",
                                  source_name, domain, self.max_retries)

            # If all APIs returned 0 results, trigger fallback to SubDomz.sh
            if not results:
                logger.warning(
                    "CRITICAL: All Python APIs failed or returned 0 results for %s. "
                    "Failed APIs: %s. Falling back to SubDomz.sh script.",
                    domain, ", ".join(failed_apis)
                )
                raise ValueError("All Python APIs failed or returned empty results")

            logger.info(
                "SubDomz Python enumeration completed for %s: %d total subdomains. "
                "Successful APIs: %s. Failed APIs: %s",
                domain, len(results),
                ", ".join(successful_apis) if successful_apis else "None",
                ", ".join(failed_apis) if failed_apis else "None"
            )
            return self._dedupe(sorted(results), domain)

        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("SubDomz Python path failed for %s: %s. Attempting fallback to SubDomz.sh",
                          domain, exc)
            return self._fallback_script(domain)

    def _fallback_script(self, domain: str) -> List[str]:
        """Fallback to SubDomz.sh bash script when Python APIs fail."""
        script_path = self.config.path or "./SubDomz.sh"
        if not Path(script_path).exists():
            logger.error(
                "CRITICAL: SubDomz.sh script not found at %s. "
                "Cannot perform subdomain enumeration for %s. "
                "Please ensure SubDomz.sh exists in the project root.",
                script_path, domain
            )
            return []

        logger.info("Executing SubDomz.sh fallback script for %s", domain)
        cmd = ["bash", script_path, "-d", domain, "-s"]  # -s for silent mode
        try:
            results = self._dedupe(self._run_command(cmd), domain)
            logger.info("SubDomz.sh returned %d subdomains for %s", len(results), domain)
            return results
        except Exception as exc:
            logger.error("SubDomz.sh script failed for %s: %s", domain, exc)
            return []

    def _retry_with_backoff(self, func, domain: str, source_name: str):
        """Execute function with exponential backoff retry logic."""
        last_exception = None

        for attempt in range(1, self.max_retries + 1):
            try:
                result = func(domain)
                if attempt > 1:
                    logger.info("%s API succeeded on attempt %d for %s",
                               source_name, attempt, domain)
                return result
            except Exception as exc:
                last_exception = exc
                if attempt < self.max_retries:
                    wait_time = self.retry_backoff ** attempt
                    logger.warning(
                        "%s API failed (attempt %d/%d) for %s: %s. "
                        "Retrying in %.1f seconds...",
                        source_name, attempt, self.max_retries, domain, exc, wait_time
                    )
                    time.sleep(wait_time)
                else:
                    logger.warning(
                        "%s API failed after %d attempts for %s: %s",
                        source_name, self.max_retries, domain, exc
                    )

        # If all retries failed, return empty set
        return set()

    def _fetch_crt(self, domain: str) -> Set[str]:
        """Fetch subdomains from crt.sh Certificate Transparency logs."""
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            resp = self.session.get(url, timeout=self.http_timeout)
            resp.raise_for_status()
            data = resp.json()

            if not data:
                logger.warning("crt.sh returned empty response for %s", domain)
                return set()

        except requests.exceptions.Timeout as exc:
            logger.warning("crt.sh lookup timed out after %d seconds for %s",
                          self.http_timeout, domain)
            raise  # Re-raise to trigger retry
        except requests.exceptions.RequestException as exc:
            logger.warning("crt.sh HTTP request failed for %s: %s", domain, exc)
            raise  # Re-raise to trigger retry
        except ValueError as exc:
            logger.warning("crt.sh returned invalid JSON for %s: %s", domain, exc)
            raise  # Re-raise to trigger retry
        except Exception as exc:
            logger.warning("crt.sh unexpected error for %s: %s", domain, exc)
            raise  # Re-raise to trigger retry

        hosts: Set[str] = set()
        for entry in data[: self.max_results]:
            name_value = (entry or {}).get("name_value", "")
            for line in name_value.splitlines():
                line = line.replace("*.", "").strip().lower()
                if domain in line:
                    hosts.add(line)
        return hosts

    def _fetch_bufferover(self, domain: str) -> Set[str]:
        """Fetch subdomains from BufferOver DNS database."""
        url = f"https://dns.bufferover.run/dns?q={domain}"
        try:
            resp = self.session.get(url, timeout=self.http_timeout)
            resp.raise_for_status()
            data = resp.json()

            if not data or not data.get("FDNS_A"):
                logger.warning("BufferOver returned empty/no FDNS_A data for %s", domain)
                return set()

        except requests.exceptions.Timeout:
            logger.warning("BufferOver lookup timed out after %d seconds for %s",
                          self.http_timeout, domain)
            raise  # Re-raise to trigger retry
        except requests.exceptions.RequestException as exc:
            logger.warning("BufferOver HTTP request failed for %s: %s", domain, exc)
            raise  # Re-raise to trigger retry
        except ValueError as exc:
            logger.warning("BufferOver returned invalid JSON for %s: %s", domain, exc)
            raise  # Re-raise to trigger retry
        except Exception as exc:
            logger.warning("BufferOver unexpected error for %s: %s", domain, exc)
            raise  # Re-raise to trigger retry

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
        """Fetch subdomains from Wayback Machine CDX API."""
        url = "https://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"*.{domain}",  # Fixed: removed /* to get more results
            "output": "text",  # Text is faster than JSON
            "fl": "original",
            "collapse": "urlkey",
            # No limit - get all archived URLs
        }
        try:
            resp = self.session.get(url, params=params, timeout=self.http_timeout)
            resp.raise_for_status()
            text = resp.text

            if not text or not text.strip():
                logger.warning("Wayback Machine returned empty response for %s", domain)
                return set()

        except requests.exceptions.Timeout:
            logger.warning("Wayback Machine lookup timed out after %d seconds for %s",
                          self.http_timeout, domain)
            raise  # Re-raise to trigger retry
        except requests.exceptions.RequestException as exc:
            logger.warning("Wayback Machine HTTP request failed for %s: %s", domain, exc)
            raise  # Re-raise to trigger retry
        except Exception as exc:
            logger.warning("Wayback Machine unexpected error for %s: %s", domain, exc)
            raise  # Re-raise to trigger retry

        hosts = set()
        # Extract hostname from each URL - fixed regex to capture full hostname
        pattern = re.compile(r"https?://([^/:]+)")
        for line in text.splitlines():
            match = pattern.search(line)
            if match:
                host = match.group(1).lower()
                # Only keep hosts that end with our domain
                if host.endswith(f".{domain}") or host == domain:
                    hosts.add(host)
        return hosts
