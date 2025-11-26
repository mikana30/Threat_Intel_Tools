#!/usr/bin/env python3
"""
httpx-based HTTP Probe with Technology Detection

Integrates the httpx tool for fast, comprehensive web probing:
- HTTP/HTTPS testing with automatic protocol detection
- Server header extraction
- Basic technology detection (title, status codes, content length)
- Stealth options (custom user-agent, rate limiting)
- CDN detection
- Screenshot support

Outputs enriched CSV compatible with downstream tools.
"""

import argparse
import csv
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional
import yaml

from dev_mode import get_target_cap, load_env_settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/httpx_probe.log", mode="w"),
        logging.StreamHandler()
    ],
)
logger = logging.getLogger("httpx_probe")


class HttpxConfig:
    """Configuration loader for httpx probe"""

    def __init__(self, config_path: str):
        self.config = {}
        if Path(config_path).exists():
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f) or {}
        else:
            logger.warning(f"Config file not found: {config_path}, using defaults")
            self.config = self._get_defaults()

    def _get_defaults(self) -> dict:
        """Default configuration"""
        return {
            'general': {
                'timeout': 10,
                'retries': 2,
                'threads': 50,
                'rate_limit': 150,
                'max_redirects': 5
            },
            'detection': {
                'tech_detect': True,
                'cdn_detect': True,
                'title_extract': True,
                'content_length': True
            },
            'stealth': {
                'enabled': False,
                'random_agent': False,
                'custom_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            'filters': {
                'status_codes': [],  # Empty = all codes
                'exclude_cdn': False,
                'min_content_length': 0
            }
        }

    def get(self, key: str, default=None):
        """Get config value with dot notation"""
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        return value


def find_httpx_binary() -> Optional[str]:
    """
    Locate httpx binary - prefer ProjectDiscovery version from ~/go/bin

    Returns:
        Path to httpx binary or None if not found
    """
    candidates = [
        Path.home() / "go" / "bin" / "httpx",
        Path("/usr/local/bin/httpx"),
        Path("/usr/bin/httpx")
    ]

    for candidate in candidates:
        if candidate.exists():
            # Verify it's the ProjectDiscovery version
            try:
                result = subprocess.run(
                    [str(candidate), "-version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                # Check both stdout and stderr (httpx outputs to stderr)
                output = result.stdout + result.stderr
                if "projectdiscovery.io" in output:
                    logger.info(f"Using ProjectDiscovery httpx from: {candidate}")
                    # Extract version info
                    for line in output.split('\n'):
                        if "Version" in line:
                            logger.info(line.strip())
                            break
                    return str(candidate)
                else:
                    logger.warning(f"Found httpx at {candidate} but it's not ProjectDiscovery version")
            except Exception as e:
                logger.warning(f"Error checking {candidate}: {e}")
                continue

    return None


def check_httpx_installed() -> bool:
    """Check if httpx is installed"""
    return find_httpx_binary() is not None


def install_httpx() -> bool:
    """Attempt to install httpx via go install"""
    logger.info("Attempting to install httpx...")
    try:
        result = subprocess.run(
            ['go', 'install', '-v', 'github.com/projectdiscovery/httpx/cmd/httpx@latest'],
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode == 0:
            logger.info("httpx installed successfully")
            return True
        else:
            logger.error(f"Failed to install httpx: {result.stderr}")
            return False
    except FileNotFoundError:
        logger.error("Go is not installed. Cannot auto-install httpx.")
        logger.info("Install manually: https://github.com/projectdiscovery/httpx")
        return False
    except Exception as e:
        logger.error(f"Error installing httpx: {e}")
        return False


def run_httpx(
    hosts: List[str],
    config: HttpxConfig,
    output_json: Path
) -> bool:
    """
    Run httpx on the host list and capture JSON output

    Returns True if successful, False otherwise
    """
    # Find httpx binary
    httpx_binary = find_httpx_binary()
    if not httpx_binary:
        logger.error("ProjectDiscovery httpx not found")
        return False

    # Build httpx command with stealth flags
    cmd = [httpx_binary, '-json']

    # General settings
    cmd.extend(['-timeout', str(config.get('general.timeout', 10))])
    cmd.extend(['-retries', str(config.get('general.retries', 2))])
    cmd.extend(['-threads', str(config.get('general.threads', 50))])
    cmd.extend(['-rate-limit', str(config.get('general.rate_limit', 50))])  # Default to 50 for stealth
    cmd.extend(['-max-redirects', str(config.get('general.max_redirects', 5))])

    # Stealth and detection flags as requested
    cmd.append('-sc')               # Show status codes (short form)
    cmd.append('-title')            # Extract page titles
    cmd.append('-td')               # Technology detection (short form)
    cmd.append('-cdn')              # CDN/WAF detection (enabled by default, explicit here)
    cmd.append('-server')           # Server header
    cmd.append('-method')           # HTTP method used
    cmd.append('-cl')               # Content-length (short form)
    cmd.append('-ct')               # Content-type (short form)
    cmd.append('-location')         # Location header (redirects)
    cmd.append('-websocket')        # WebSocket support
    cmd.append('-rt')               # Response time (short form)
    cmd.append('-ip')               # Resolved IP
    cmd.append('-cname')            # CNAME records
    cmd.append('-http2')            # HTTP/2 support
    cmd.append('-pipeline')         # HTTP pipelining

    # Stealth User-Agent (browser-like)
    custom_agent = config.get('stealth.custom_agent',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
    )
    cmd.extend(['-header', f'User-Agent: {custom_agent}'])

    # Status code filter (if specified)
    status_codes = config.get('filters.status_codes', [])
    if status_codes:
        codes_str = ','.join(map(str, status_codes))
        cmd.extend(['-mc', codes_str])  # Match codes

    # Additional flags for reliability
    cmd.append('-follow-redirects')
    cmd.append('-follow-host-redirects')
    cmd.append('-no-color')
    cmd.append('-silent')

    # Output to JSON file
    cmd.extend(['-o', str(output_json)])

    logger.info(f"Running httpx on {len(hosts)} hosts...")
    logger.debug(f"httpx command: {' '.join(cmd)}")

    try:
        # Write hosts to temporary file for httpx input
        hosts_file = output_json.parent / 'httpx_input_hosts.txt'
        hosts_file.write_text('\n'.join(hosts))

        # Run httpx with stdin
        with open(hosts_file, 'r') as f:
            result = subprocess.run(
                cmd,
                stdin=f,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout for large scans
            )

        # Clean up temp file
        hosts_file.unlink()

        if result.returncode != 0:
            logger.error(f"httpx failed with return code {result.returncode}")
            if result.stderr:
                logger.error(f"httpx stderr: {result.stderr}")
            if result.stdout:
                logger.error(f"httpx stdout: {result.stdout}")
            return False

        if result.stderr:
            logger.info(f"httpx stderr: {result.stderr[:500]}")

        logger.info(f"httpx completed successfully")
        return True

    except subprocess.TimeoutExpired:
        logger.error("httpx timed out after 10 minutes")
        return False
    except Exception as e:
        logger.error(f"Error running httpx: {e}")
        return False


def parse_httpx_output(json_file: Path) -> List[Dict]:
    """
    Parse httpx JSON output into structured records

    Each record contains:
    - url: full URL tested
    - host: hostname
    - status_code: HTTP status
    - title: page title (if detected)
    - server: Server header
    - content_length: response size
    - technologies: detected technologies
    - cdn: CDN name (if detected)
    - content_type: Content-Type header
    - scheme: http or https
    """
    records = []

    if not json_file.exists():
        logger.error(f"httpx output file not found: {json_file}")
        return records

    try:
        with open(json_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)

                    record = {
                        'url': data.get('url', ''),
                        'host': data.get('host', ''),
                        'status_code': data.get('status_code', ''),
                        'title': data.get('title', ''),
                        'server': data.get('webserver', ''),
                        'content_length': data.get('content_length', ''),
                        'technologies': ', '.join(data.get('tech', [])) if data.get('tech') else '',
                        'cdn': data.get('cdn', ''),
                        'content_type': data.get('content_type', ''),
                        'scheme': data.get('scheme', ''),
                        'method': data.get('method', 'GET'),
                        'final_url': data.get('final_url', ''),
                        'tls_version': data.get('tls', {}).get('version', '') if isinstance(data.get('tls'), dict) else '',
                        'response_time': data.get('time', '')
                    }

                    records.append(record)

                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse JSON line: {e}")
                    continue

        logger.info(f"Parsed {len(records)} records from httpx output")
        return records

    except Exception as e:
        logger.error(f"Error parsing httpx output: {e}")
        return []


def apply_filters(records: List[Dict], config: HttpxConfig) -> List[Dict]:
    """Apply post-processing filters"""
    filtered = records

    # Filter by CDN
    if config.get('filters.exclude_cdn', False):
        before = len(filtered)
        filtered = [r for r in filtered if not r.get('cdn')]
        logger.info(f"CDN filter: {before} -> {len(filtered)} records")

    # Filter by content length
    min_length = config.get('filters.min_content_length', 0)
    if min_length > 0:
        before = len(filtered)
        filtered = [
            r for r in filtered
            if r.get('content_length') and int(r['content_length']) >= min_length
        ]
        logger.info(f"Content length filter (>={min_length}): {before} -> {len(filtered)} records")

    return filtered


def write_csv_output(records: List[Dict], output_path: Path):
    """Write records to CSV file"""
    if not records:
        logger.warning("No records to write to CSV")
        # Write empty CSV with headers
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['url', 'host', 'status_code', 'title', 'server',
                           'content_length', 'technologies', 'cdn', 'content_type',
                           'scheme', 'method', 'final_url', 'tls_version', 'response_time'])
        return

    # Get all unique keys from records
    fieldnames = list(records[0].keys())

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    logger.info(f"Wrote {len(records)} records to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="httpx-based HTTP probe with technology detection"
    )
    parser.add_argument(
        "--resolved-json",
        required=True,
        help="Path to resolved.json from DNS resolution stage"
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to output CSV file"
    )
    parser.add_argument(
        "--config",
        default="config/httpx.yml",
        help="Path to httpx configuration file"
    )
    parser.add_argument(
        "--env-config",
        default="config/environment.yml",
        help="Environment config for dev mode caps"
    )
    parser.add_argument(
        "--auto-install",
        action="store_true",
        help="Automatically install httpx if not found"
    )

    args = parser.parse_args()

    # Check if httpx is installed
    if not check_httpx_installed():
        logger.error("httpx is not installed")
        if args.auto_install:
            if not install_httpx():
                logger.error("Failed to install httpx. Exiting.")
                sys.exit(1)
        else:
            logger.error("Install httpx: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
            logger.error("Or use --auto-install flag")
            sys.exit(1)

    # Load configuration
    config = HttpxConfig(args.config)

    # Load resolved hosts
    resolved_path = Path(args.resolved_json)
    if not resolved_path.exists():
        logger.error(f"Resolved JSON not found: {resolved_path}")
        sys.exit(1)

    resolved = json.loads(resolved_path.read_text())
    hosts = sorted(resolved.keys())

    logger.info(f"Loaded {len(hosts)} resolved hosts")

    # Apply dev mode cap
    env_settings = load_env_settings(Path(args.env_config))
    cap = get_target_cap(env_settings)
    if cap:
        hosts = hosts[:cap]
        logger.info(f"Dev cap active ({cap}) - limiting to {len(hosts)} hosts")

    if not hosts:
        logger.warning("No hosts to probe")
        # Write empty output
        write_csv_output([], Path(args.output))
        sys.exit(0)

    # Create temp JSON output path
    output_path = Path(args.output)
    json_output = output_path.parent / 'httpx_raw_output.json'

    # Run httpx
    success = run_httpx(hosts, config, json_output)

    if not success:
        logger.error("httpx execution failed")
        sys.exit(1)

    # Parse httpx output
    records = parse_httpx_output(json_output)

    # Apply filters
    records = apply_filters(records, config)

    # Write CSV output
    write_csv_output(records, output_path)

    # Clean up temp JSON
    if json_output.exists():
        json_output.unlink()

    logger.info(f"httpx probe completed: {len(records)} live hosts found")

    # Summary stats
    if records:
        status_counts = {}
        for r in records:
            status = r.get('status_code', 'unknown')
            status_counts[status] = status_counts.get(status, 0) + 1

        logger.info("Status code distribution:")
        for status, count in sorted(status_counts.items()):
            logger.info(f"  {status}: {count}")


if __name__ == "__main__":
    main()
