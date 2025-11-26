#!/usr/bin/env python3
"""
Unified Technology Detection Service

Consolidates three separate tech detection approaches:
1. Server-side tech detection via whatweb (backends, CMS, servers)
2. Client-side JS library detection from HTML (jQuery, React, Angular, etc.)
3. Framework detection (Bootstrap, Tailwind, etc.)
4. Default page detection (Apache, Nginx, IIS, etc.)
5. Debug endpoint discovery

Config-driven from config/tech_detection.yml
Supports dev mode awareness

NOTE: This tool provides DEEP technology detection that complements httpx_probe.py.
      httpx does basic tech detection during HTTP probing (fast, broad).
      This tool does comprehensive analysis on live hosts (slow, detailed).
      Use httpx for initial discovery, this tool for deep analysis.
"""

import os
import sys
import argparse
import csv
import json
import subprocess
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from typing import Dict, List, Tuple, Optional
import requests
from bs4 import BeautifulSoup
import yaml

# Add utils directory to path for timeout module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'utils'))
try:
    from timeout import timeout
except ImportError as e:
    print(f"FATAL: utils.timeout module not available: {e}", file=sys.stderr)
    print("Ensure you are running from the workspace root:", file=sys.stderr)
    print("  cd /home/mikana/Threat_Intel_Tools", file=sys.stderr)
    print("  python3 tech_detection_service.py [args]", file=sys.stderr)
    sys.exit(1)

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TechDetectionConfig:
    """Load and validate tech detection configuration"""

    def __init__(self, config_path: str):
        """Load configuration from YAML file"""
        if not os.path.exists(config_path):
            logger.warning(f"Config file not found: {config_path}, using defaults")
            self.config = self._get_default_config()
        else:
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f) or {}

    def _get_default_config(self) -> dict:
        """Return default configuration"""
        return {
            'general': {
                'max_workers': 5,
                'timeout': 10,
                'verify_ssl': False,
                'follow_redirects': True
            },
            'whatweb': {
                'enabled': True,
                'normalize_names': True
            },
            'javascript_libraries': {
                'enabled': True,
                'detect_versions': True
            },
            'frameworks': {
                'enabled': True
            },
            'default_pages': {
                'enabled': True
            },
            'debug_endpoints': {
                'enabled': True,
                'timeout': 3
            },
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

    def get(self, key: str, default=None):
        """Get configuration value with dot notation"""
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


class ServerTechDetector:
    """Detect server-side technologies using whatweb"""

    NAME_MAP = {
        "Apache": "Apache",
        "HTTPServer": "Apache",
        "nginx": "Nginx",
        "Tomcat": "Tomcat",
        "Jenkins": "Jenkins",
        "OpenSSH": "OpenSSH",
        "OpenSSL": "OpenSSL",
        "PHP": "PHP",
        "MySQL": "MySQL",
        "PostgreSQL": "PostgreSQL",
        "Redis": "Redis",
        "MongoDB": "MongoDB",
        "WordPress": "WordPress",
        "Drupal": "Drupal",
        "Joomla": "Joomla",
        "Express": "Express",
        "Django": "Django",
        "Ruby": "Ruby",
        "Ruby on Rails": "Rails",
        "ASP.NET": "ASP.NET",
        "IIS": "IIS",
        "Windows": "Windows",
        "Linux": "Linux",
        "CentOS": "CentOS",
        "Ubuntu": "Ubuntu",
        "Debian": "Debian",
        "Fedora": "Fedora",
        "Alpine": "Alpine",
        "Docker": "Docker",
        "Kubernetes": "Kubernetes",
    }

    def __init__(self, config: TechDetectionConfig):
        self.config = config
        self.normalize = config.get('whatweb.normalize_names', True)

    def normalize_name(self, name: str) -> str:
        """Normalize technology name"""
        return self.NAME_MAP.get(name, name)

    def detect(self, url: str) -> Dict[str, str]:
        """Run whatweb and return detected technologies"""
        if not url.startswith("http"):
            url = "http://" + url

        timeout_seconds = self.config.get('general.timeout', 10)

        try:
            with timeout(timeout_seconds + 5):  # Add 5s buffer to subprocess timeout
                result = subprocess.run(
                    ['whatweb', '--log-json=-', url],
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds
                )
                if result.returncode != 0:
                    logger.debug(f"whatweb failed for {url}: {result.stderr}")
                    return {}
        except FileNotFoundError:
            logger.critical("whatweb not found in PATH - technology detection cannot proceed")
            logger.critical("Install whatweb: sudo apt-get install whatweb")
            logger.critical("Or ensure it's in your PATH")
            sys.exit(1)
        except subprocess.TimeoutExpired:
            logger.warning(f"whatweb subprocess timeout for {url}")
            return {}
        except TimeoutError as e:
            logger.warning(f"whatweb operation timeout for {url}: {e}")
            return {}
        except Exception as e:
            logger.error(f"whatweb error for {url}: {e}")
            return {}

        techs = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line == ',':
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            for tname, info in entry.get('plugins', {}).items():
                version = info.get('version') or info.get('string') or "Unknown"
                if isinstance(version, list):
                    version = " ".join(version)
                normalized = self.normalize_name(tname) if self.normalize else tname
                techs[f"Backend_{normalized}"] = version

        return techs


class ClientTechDetector:
    """Detect client-side JS libraries and frameworks"""

    LIBRARY_PATTERNS = {
        "jquery": re.compile(r"jquery[.-](\d+\.\d+(\.\d+)?)\.js", re.I),
        "react": re.compile(r"react[.-](\d+\.\d+(\.\d+)?)\.js", re.I),
        "angular": re.compile(r"angular[.-](\d+\.\d+(\.\d+)?)\.js", re.I),
        "vue": re.compile(r"vue[.-](\d+\.\d+(\.\d+)?)\.js", re.I),
        "bootstrap": re.compile(r"bootstrap[.-](\d+\.\d+(\.\d+)?)\.(?:js|css)", re.I),
        "tailwind": re.compile(r"tailwind[.-](\d+\.\d+(\.\d+)?)\.css", re.I),
        "foundation": re.compile(r"foundation[.-](\d+\.\d+(\.\d+)?)\.(?:js|css)", re.I),
        "bulma": re.compile(r"bulma[.-](\d+\.\d+(\.\d+)?)\.css", re.I),
        "moment": re.compile(r"moment[.-](\d+\.\d+(\.\d+)?)\.js", re.I),
        "underscore": re.compile(r"underscore[.-](\d+\.\d+(\.\d+)?)\.js", re.I),
        "lodash": re.compile(r"lodash[.-](\d+\.\d+(\.\d+)?)\.js", re.I),
        "d3": re.compile(r"d3[.-](\d+\.\d+(\.\d+)?)\.js", re.I),
        "typescript": re.compile(r"typescript[.-](\d+\.\d+(\.\d+)?)\.js", re.I),
    }

    FRAMEWORK_PATTERNS = {
        "react": re.compile(r"(?:react|reactDOM)", re.I),
        "vue": re.compile(r"vue\.js|vue\.esm", re.I),
        "angular": re.compile(r"angular\.js", re.I),
        "next.js": re.compile(r"__NEXT_DATA__|next\.js", re.I),
        "gatsby": re.compile(r"gatsby", re.I),
        "svelte": re.compile(r"svelte", re.I),
    }

    DEFAULT_SIGNATURES = {
        "apache": ["It works!", "Apache2 Ubuntu Default Page"],
        "nginx": ["Welcome to nginx!"],
        "iis": ["IIS Windows Server", "Welcome to IIS"],
        "tomcat": ["Apache Tomcat"],
        "ngrok": ["Tunnel", "ngrok"]
    }

    DEBUG_PATHS = [
        "/debug", "/admin/debug", "/test.js", "/config.js", "/_profiler",
        "/phpinfo.php", "/info.php", "/.env", "/actuator/health", "/api/debug"
    ]

    def __init__(self, config: TechDetectionConfig):
        self.config = config
        self.headers = {
            'User-Agent': config.get(
                'user_agent',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
        }

    def fetch_html(self, domain: str) -> Tuple[Optional[str], Optional[str]]:
        """Fetch HTML content from domain, return (html, url)"""
        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{domain}"
                resp = requests.get(
                    url,
                    headers=self.headers,
                    timeout=self.config.get('general.timeout', 10),
                    verify=self.config.get('general.verify_ssl', False),
                    allow_redirects=self.config.get('general.follow_redirects', True)
                )
                if resp.status_code == 200:
                    return resp.text, url
            except requests.RequestException as e:
                logger.debug(f"Failed to fetch {scheme}://{domain}: {e}")
                continue
        return None, None

    def detect_js_libraries(self, html: str) -> Dict[str, str]:
        """Detect JS libraries from HTML script tags"""
        if not self.config.get('javascript_libraries.enabled', True):
            return {}

        libs = {}
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for script in soup.find_all("script", src=True):
                src = script.get('src', '')
                for lib, pattern in self.LIBRARY_PATTERNS.items():
                    match = pattern.search(src)
                    if match:
                        version = match.group(1)
                        libs[f"JS_{lib.capitalize()}"] = version
        except Exception as e:
            logger.debug(f"Error detecting JS libraries: {e}")

        return libs

    def detect_frameworks(self, html: str) -> Dict[str, str]:
        """Detect frameworks from HTML content"""
        if not self.config.get('frameworks.enabled', True):
            return {}

        frameworks = {}
        try:
            soup = BeautifulSoup(html, 'html.parser')
            scripts_text = ' '.join([
                script.string or '' for script in soup.find_all('script')
                if script.string
            ])

            for framework, pattern in self.FRAMEWORK_PATTERNS.items():
                if pattern.search(scripts_text) or pattern.search(html):
                    frameworks[f"Framework_{framework.capitalize()}"] = "Detected"
        except Exception as e:
            logger.debug(f"Error detecting frameworks: {e}")

        return frameworks

    def detect_default_page(self, html: str) -> Optional[str]:
        """Detect if page is a default server page"""
        if not self.config.get('default_pages.enabled', True):
            return None

        for server, signatures in self.DEFAULT_SIGNATURES.items():
            if any(sig.lower() in html.lower() for sig in signatures):
                return server
        return None

    def find_debug_paths(self, domain: str) -> List[str]:
        """Check for exposed debug endpoints"""
        if not self.config.get('debug_endpoints.enabled', True):
            return []

        found_paths = []
        timeout = self.config.get('debug_endpoints.timeout', 3)

        for path in self.DEBUG_PATHS:
            for scheme in ["https", "http"]:
                try:
                    url = f"{scheme}://{domain}{path}"
                    r = requests.get(
                        url,
                        headers=self.headers,
                        timeout=timeout,
                        verify=False,
                        allow_redirects=False
                    )
                    if r.status_code in [200, 401, 403]:  # Found or restricted
                        found_paths.append(path)
                        break
                except requests.RequestException:
                    continue

        return found_paths

    def detect(self, domain: str) -> Dict[str, any]:
        """Run all client-side detection"""
        html, actual_url = self.fetch_html(domain)

        result = {
            'js_libraries': {},
            'frameworks': {},
            'default_page': None,
            'debug_paths': []
        }

        if html:
            result['js_libraries'] = self.detect_js_libraries(html)
            result['frameworks'] = self.detect_frameworks(html)
            result['default_page'] = self.detect_default_page(html)

        result['debug_paths'] = self.find_debug_paths(domain)

        return result


class TechDetectionService:
    """Unified technology detection service"""

    def __init__(self, config: TechDetectionConfig, dev_mode: bool = False):
        self.config = config
        self.dev_mode = dev_mode
        self.server_detector = ServerTechDetector(config)
        self.client_detector = ClientTechDetector(config)
        self.max_workers = config.get('general.max_workers', 5)

    def scan_target(self, target: str) -> Dict:
        """Scan a single target for all technologies"""
        logger.info(f"Scanning: {target}")

        # Get just domain/IP for client detection
        domain = target.split('/')[0] if '/' in target else target

        results = {
            'target': target,
            'domain': domain,
            'server_tech': {},
            'client_tech': {},
            'default_page': None,
            'debug_paths': []
        }

        # Server-side tech detection
        if self.config.get('whatweb.enabled', True):
            try:
                results['server_tech'] = self.server_detector.detect(target)
            except Exception as e:
                logger.error(f"Server tech detection failed for {target}: {e}")

        # Client-side tech detection
        try:
            client_results = self.client_detector.detect(domain)
            results['client_tech'].update(client_results['js_libraries'])
            results['client_tech'].update(client_results['frameworks'])
            results['default_page'] = client_results['default_page']
            results['debug_paths'] = client_results['debug_paths']
        except Exception as e:
            logger.error(f"Client tech detection failed for {domain}: {e}")

        return results

    def scan_targets(self, targets: List[str]) -> List[Dict]:
        """Scan multiple targets with concurrency"""
        results = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.scan_target, t) for t in targets]
            for future in tqdm(
                as_completed(futures),
                total=len(targets),
                desc="Tech Detection",
                disable=self.dev_mode
            ):
                try:
                    results.append(future.result())
                except Exception as e:
                    logger.error(f"Scan failed: {e}")

        return results

    def consolidate_results(self, scan_results: List[Dict]) -> Tuple[List[str], List[Dict]]:
        """Consolidate results into flat CSV format"""
        all_techs = set()

        # Collect all unique tech names
        for result in scan_results:
            all_techs.update(result['server_tech'].keys())
            all_techs.update(result['client_tech'].keys())

        headers = [
            'target',
            'domain',
            'default_page',
            'debug_paths'
        ] + sorted(list(all_techs))

        # Build rows
        rows = []
        for result in scan_results:
            row = {
                'target': result['target'],
                'domain': result['domain'],
                'default_page': result['default_page'] or '',
                'debug_paths': '; '.join(result['debug_paths']) if result['debug_paths'] else ''
            }

            # Add all technologies
            all_tech = {**result['server_tech'], **result['client_tech']}
            for tech in all_techs:
                row[tech] = all_tech.get(tech, '')

            rows.append(row)

        return headers, rows

    def save_csv(self, headers: List[str], rows: List[Dict], output_file: str):
        """Save results to CSV file"""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)
        logger.info(f"Results saved to: {output_file}")

    def save_json(self, results: List[Dict], output_file: str):
        """Save results to JSON file"""
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        logger.info(f"JSON results saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Unified Technology Detection Service"
    )
    parser.add_argument(
        "-i", "--input",
        required=True,
        help="Input file (one URL/domain per line)"
    )
    parser.add_argument(
        "-o", "--output",
        required=True,
        help="Output CSV file"
    )
    parser.add_argument(
        "-j", "--json-output",
        help="Optional JSON output file"
    )
    parser.add_argument(
        "-c", "--config",
        default="config/tech_detection.yml",
        help="Config file (default: config/tech_detection.yml)"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=5,
        help="Number of concurrent threads"
    )
    parser.add_argument(
        "--dev-mode",
        action="store_true",
        help="Development mode (quiet output)"
    )
    parser.add_argument(
        "--env-config",
        help="Environment configuration file"
    )

    args = parser.parse_args()

    # Load targets
    try:
        with open(args.input, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"Failed to read input file: {e}")
        sys.exit(1)

    if not targets:
        logger.error("No targets found in input file")
        sys.exit(1)

    logger.info(f"Loaded {len(targets)} targets")

    # Load configuration
    config = TechDetectionConfig(args.config)
    if args.threads:
        config.config['general']['max_workers'] = args.threads

    # Run detection service
    service = TechDetectionService(config, dev_mode=args.dev_mode)
    scan_results = service.scan_targets(targets)

    # Consolidate and save results
    headers, rows = service.consolidate_results(scan_results)
    service.save_csv(headers, rows, args.output)

    if args.json_output:
        service.save_json(scan_results, args.json_output)

    logger.info(f"Scanning complete. Scanned {len(scan_results)} targets")


if __name__ == "__main__":
    main()
