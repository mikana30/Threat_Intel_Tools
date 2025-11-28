import logging
from urllib.parse import urlparse
from typing import List
import subprocess
import time

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

        # Build command with resilience flags
        # Default timeout from config, or 120 seconds (increased from gau's default 45s)
        timeout = self.config.timeout or 120
        # Default retries from config flags, or 3 retries
        retries = 3
        threads = 2

        # Check if custom flags are provided in config
        custom_flags = self.config.flags or []

        # Build base command with resilience settings
        cmd = ["gau", domain]

        # Add timeout flag if not already in custom flags
        if not any("--timeout" in str(flag) for flag in custom_flags):
            cmd.extend(["--timeout", str(timeout)])

        # Add retries flag if not already in custom flags
        if not any("--retries" in str(flag) for flag in custom_flags):
            cmd.extend(["--retries", str(retries)])

        # Add threads flag if not already in custom flags
        if not any("--threads" in str(flag) for flag in custom_flags):
            cmd.extend(["--threads", str(threads)])

        # Add verbose flag for better error visibility
        if not any("--verbose" in str(flag) for flag in custom_flags):
            cmd.append("--verbose")

        # Add any custom flags from config
        cmd.extend(custom_flags)

        # Execute with enhanced error handling and retry logic
        max_attempts = 2  # Try twice if first attempt fails completely
        last_error = None

        for attempt in range(1, max_attempts + 1):
            try:
                logger.info(f"[gau] Attempting to fetch URLs for {domain} (attempt {attempt}/{max_attempts})")
                logger.debug(f"[gau] Running command: {' '.join(cmd)}")

                # Run the command with timeout
                proc = subprocess.run(
                    cmd,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=timeout + 30  # Add buffer to subprocess timeout
                )

                # Check for errors
                if proc.returncode != 0:
                    error_msg = proc.stderr.strip() if proc.stderr else "Unknown error"
                    logger.warning(
                        f"[gau] Command exited with code {proc.returncode} on attempt {attempt}: {error_msg}"
                    )
                    last_error = error_msg

                    # If this is not the last attempt, wait before retry
                    if attempt < max_attempts:
                        wait_time = 5 * attempt  # Exponential backoff: 5s, 10s
                        logger.warning(f"[gau] Retrying in {wait_time} seconds...")
                        time.sleep(wait_time)
                        continue
                else:
                    # Success - process output
                    out_lines = proc.stdout.splitlines()

                    if not out_lines:
                        logger.warning(
                            f"[gau] No URLs returned for {domain}. This may indicate API failures or no archived data."
                        )
                        # Don't retry if command succeeded but returned no data
                        # This is a legitimate result (domain has no archived URLs)
                        return []

                    logger.info(f"[gau] Retrieved {len(out_lines)} URLs for {domain}")

                    # Parse hostnames from URLs
                    hosts = []
                    parse_errors = 0
                    for line in out_lines:
                        try:
                            hostname = urlparse(line.strip()).hostname
                            if hostname:
                                hosts.append(hostname)
                        except (ValueError, Exception) as e:
                            parse_errors += 1
                            if parse_errors <= 5:  # Log first 5 parse errors
                                logger.debug(f"[gau] Failed to parse URL: {line.strip()[:100]}")

                    if parse_errors > 0:
                        logger.warning(f"[gau] Failed to parse {parse_errors} URLs (non-critical)")

                    unique_hosts = self._dedupe(hosts, domain)
                    logger.info(f"[gau] Found {len(unique_hosts)} unique subdomains for {domain}")

                    if len(unique_hosts) == 0 and len(hosts) > 0:
                        logger.warning(
                            f"[gau] Retrieved {len(hosts)} hosts but none matched domain {domain}. "
                            f"This may indicate incorrect domain filtering."
                        )

                    return unique_hosts

            except subprocess.TimeoutExpired:
                logger.warning(
                    f"[gau] Command timeout after {timeout + 30}s on attempt {attempt}. "
                    f"The API providers may be slow or unresponsive."
                )
                last_error = f"Timeout after {timeout + 30}s"

                if attempt < max_attempts:
                    wait_time = 5 * attempt
                    logger.warning(f"[gau] Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue

            except Exception as e:
                logger.warning(f"[gau] Unexpected error on attempt {attempt}: {str(e)}")
                last_error = str(e)

                if attempt < max_attempts:
                    wait_time = 5 * attempt
                    logger.warning(f"[gau] Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue

        # All attempts failed
        logger.warning(
            f"[gau] Failed to retrieve data for {domain} after {max_attempts} attempts. "
            f"Last error: {last_error}. Returning empty result to prevent incomplete data."
        )
        return []
