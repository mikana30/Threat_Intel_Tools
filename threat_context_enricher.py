#!/usr/bin/env python3
"""
Threat Context Enrichment System
Passive enrichment - maps detected services/technologies to CVE vulnerabilities and MITRE ATT&CK techniques
"""

import os
import sys
import json
import csv
import re
import time
import sqlite3
import argparse
import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
from urllib.parse import quote
import yaml

try:
    import requests
except ImportError:
    print("ERROR: requests library not found. Install with: pip3 install requests")
    sys.exit(1)

# Import retry utility
try:
    from utils.api_retry import retry_with_backoff
except ImportError as e:
    print(f"FATAL: utils.api_retry module not available: {e}", file=sys.stderr)
    print("Ensure you are running from the workspace root:", file=sys.stderr)
    print("  cd /home/mikana/Threat_Intel_Tools", file=sys.stderr)
    print("  python3 threat_context_enricher.py [args]", file=sys.stderr)
    sys.exit(1)


class CVECache:
    """SQLite-based cache for CVE lookups to avoid repeated API calls"""

    def __init__(self, db_path: str, ttl: int = 2592000):
        self.db_path = db_path
        self.ttl = ttl  # Time-to-live in seconds
        self.lock = threading.RLock()
        self._init_db()

    def _init_db(self):
        """Initialize SQLite database with schema"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        with self.lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()

            # Create CVE cache table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cve_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service_name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    cve_id TEXT NOT NULL,
                    cvss_score REAL,
                    cvss_severity TEXT,
                    description TEXT,
                    cwe_id TEXT,
                    exploit_available BOOLEAN DEFAULT 0,
                    last_updated INTEGER NOT NULL,
                    UNIQUE(service_name, version, cve_id)
                )
            ''')

            # Create index for faster lookups
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_service_version
                ON cve_cache(service_name, version)
            ''')

            # Create MITRE mapping cache table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS mitre_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    technique_id TEXT NOT NULL,
                    technique_name TEXT,
                    tactic TEXT,
                    last_updated INTEGER NOT NULL,
                    UNIQUE(cve_id, technique_id)
                )
            ''')

            conn.commit()
            conn.close()

    def get_cves(self, service_name: str, version: str, max_age: int = None) -> List[Dict]:
        """Retrieve cached CVEs for a service version"""
        if max_age is None:
            max_age = self.ttl

        cutoff_time = int(time.time()) - max_age

        with self.lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('''
                SELECT * FROM cve_cache
                WHERE service_name = ? AND version = ? AND last_updated > ?
            ''', (service_name, version, cutoff_time))

            results = [dict(row) for row in cursor.fetchall()]
            conn.close()

        return results

    def store_cve(self, service_name: str, version: str, cve_data: Dict):
        """Store CVE data in cache"""
        with self.lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()

            current_time = int(time.time())

            cursor.execute('''
                INSERT OR REPLACE INTO cve_cache
                (service_name, version, cve_id, cvss_score, cvss_severity,
                 description, cwe_id, exploit_available, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                service_name,
                version,
                cve_data.get('cve_id'),
                cve_data.get('cvss_score'),
                cve_data.get('cvss_severity'),
                cve_data.get('description'),
                cve_data.get('cwe_id'),
                cve_data.get('exploit_available', False),
                current_time
            ))

            conn.commit()
            conn.close()

    def get_mitre_techniques(self, cve_id: str) -> List[Dict]:
        """Retrieve cached MITRE ATT&CK techniques for a CVE"""
        with self.lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('''
                SELECT * FROM mitre_cache WHERE cve_id = ?
            ''', (cve_id,))

            results = [dict(row) for row in cursor.fetchall()]
            conn.close()

        return results

    def store_mitre_technique(self, cve_id: str, technique_data: Dict):
        """Store MITRE technique mapping in cache"""
        with self.lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()

            current_time = int(time.time())

            cursor.execute('''
                INSERT OR REPLACE INTO mitre_cache
                (cve_id, technique_id, technique_name, tactic, last_updated)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                cve_id,
                technique_data.get('technique_id'),
                technique_data.get('technique_name'),
                technique_data.get('tactic'),
                current_time
            ))

            conn.commit()
            conn.close()

    def cleanup_old_entries(self):
        """Remove entries older than TTL"""
        cutoff_time = int(time.time()) - self.ttl

        with self.lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = conn.cursor()

            cursor.execute('DELETE FROM cve_cache WHERE last_updated < ?', (cutoff_time,))
            cursor.execute('DELETE FROM mitre_cache WHERE last_updated < ?', (cutoff_time,))

            deleted = cursor.rowcount
            conn.commit()
            conn.close()

        return deleted


class RateLimiter:
    """Rate limiter for API calls"""

    def __init__(self, calls_per_period: int, period: int = 30):
        self.calls_per_period = calls_per_period
        self.period = period  # in seconds
        self.calls = []

    def wait_if_needed(self):
        """Wait if rate limit would be exceeded"""
        now = time.time()

        # Remove calls outside the current period
        self.calls = [call_time for call_time in self.calls if now - call_time < self.period]

        if len(self.calls) >= self.calls_per_period:
            # Need to wait
            sleep_time = self.period - (now - self.calls[0]) + 0.1
            if sleep_time > 0:
                logging.info(f"Rate limit reached, waiting {sleep_time:.2f} seconds...")
                time.sleep(sleep_time)

        self.calls.append(now)


class ThreatContextEnricher:
    """Main threat context enrichment engine"""

    def __init__(self, config_path: str, env_config_path: str = None):
        self.config = self._load_config(config_path)
        self.env_config = self._load_config(env_config_path) if env_config_path else {}

        # Initialize cache
        cache_config = self.config.get('cache', {})
        self.cache = CVECache(
            cache_config.get('database', 'cache/cve_cache.db'),
            cache_config.get('ttl', 2592000)
        )

        # Initialize rate limiters
        rate_limits = self.config.get('rate_limits', {})
        # Load API key from environment variable (secure method)
        nvd_api_key = os.getenv('NVD_API_KEY', '')
        if not nvd_api_key:
            # Fallback to config file for backward compatibility
            nvd_api_key = self.config.get('apis', {}).get('nvd', {}).get('api_key', '')
        if not nvd_api_key:
            logging.warning("NVD_API_KEY not set - using unauthenticated mode (5 req/30s limit)")
        nvd_limit = rate_limits.get('nvd_with_key', 50) if nvd_api_key else rate_limits.get('nvd_without_key', 5)

        self.nvd_limiter = RateLimiter(nvd_limit, 30)
        self.circl_limiter = RateLimiter(rate_limits.get('circl', 60), 60)
        self.global_delay = rate_limits.get('global_delay', 0.5)

        # Setup logging
        self._setup_logging()

        # MITRE ATT&CK data cache
        self.mitre_data = None

        logging.info("Threat Context Enricher initialized")

    def _load_config(self, config_path: str) -> Dict:
        """Load YAML configuration file"""
        if not config_path or not os.path.exists(config_path):
            return {}

        with open(config_path, 'r') as f:
            return yaml.safe_load(f)

    def _setup_logging(self):
        """Configure logging"""
        log_config = self.config.get('logging', {})
        log_file = log_config.get('file', 'logs/threat_enrichment.log')

        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        logging.basicConfig(
            level=getattr(logging, log_config.get('level', 'INFO')),
            format=log_config.get('format', '%(asctime)s - %(levelname)s - %(message)s'),
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )

    def extract_service_version(self, banner: str, tech_data: Dict = None) -> List[Tuple[str, str]]:
        """
        Extract service name and version from banner or tech detection data
        Returns list of (service_name, version) tuples
        """
        results = []

        # First try tech_data if available
        if tech_data:
            for tech_name, tech_version in tech_data.items():
                if tech_version and tech_version != "Unknown":
                    # Clean version string
                    version_clean = re.sub(r'[^\d.]', '', str(tech_version))
                    if version_clean:
                        results.append((tech_name, version_clean))

        # Then try banner patterns
        if banner:
            patterns = self.config.get('service_patterns', [])
            for pattern in patterns:
                match = re.search(pattern['regex'], banner, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else None
                    if version:
                        results.append((pattern['name'], version))

        return results

    @retry_with_backoff(max_retries=3, base_delay=1)
    def _make_nvd_request(self, url: str, headers: dict, timeout: int):
        """Make NVD API request with retry logic"""
        return requests.get(url, headers=headers, timeout=timeout)

    def query_nvd_api(self, service_name: str, version: str) -> List[Dict]:
        """Query NVD API for CVEs"""
        api_config = self.config.get('apis', {}).get('nvd', {})

        if not api_config.get('enabled', True):
            return []

        # Check cache first
        cached_cves = self.cache.get_cves(service_name, version)
        if cached_cves:
            logging.debug(f"Cache hit for {service_name} {version}")
            return cached_cves

        logging.info(f"Querying NVD for {service_name} {version}")

        # Build CPE name (simplified - real CPE construction is more complex)
        # Format: cpe:2.3:a:vendor:product:version
        cpe_vendor = service_name.lower().replace(' ', '_')
        cpe_product = service_name.lower().replace(' ', '_')

        # For known services, use proper CPE
        for pattern in self.config.get('service_patterns', []):
            if pattern['name'].lower() == service_name.lower():
                cpe_vendor = pattern.get('cpe_vendor', cpe_vendor)
                cpe_product = pattern.get('cpe_product', cpe_product)
                break

        cpe_name = f"cpe:2.3:a:{cpe_vendor}:{cpe_product}:{version}"

        # Rate limiting
        self.nvd_limiter.wait_if_needed()
        time.sleep(self.global_delay)

        try:
            url = f"{api_config['base_url']}?cpeName={quote(cpe_name)}"
            headers = {}

            # Use API key from environment variable (preferred) or config (fallback)
            nvd_api_key = os.getenv('NVD_API_KEY', '') or api_config.get('api_key', '')
            if nvd_api_key:
                headers['apiKey'] = nvd_api_key

            response = self._make_nvd_request(
                url,
                headers,
                api_config.get('timeout', 30)
            )

            if response.status_code == 200:
                data = response.json()
                cves = []

                for vuln in data.get('vulnerabilities', []):
                    cve = vuln.get('cve', {})
                    cve_id = cve.get('id')

                    # Extract CVSS score
                    metrics = cve.get('metrics', {})
                    cvss_score = None
                    cvss_severity = None

                    # Try CVSSv3 first, then CVSSv2
                    for metric_version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                        if metric_version in metrics and metrics[metric_version]:
                            cvss_data = metrics[metric_version][0].get('cvssData', {})
                            cvss_score = cvss_data.get('baseScore')
                            cvss_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                            break

                    # Extract description
                    descriptions = cve.get('descriptions', [])
                    description = next((d['value'] for d in descriptions if d.get('lang') == 'en'), 'No description')

                    # Extract CWE
                    weaknesses = cve.get('weaknesses', [])
                    cwe_id = None
                    if weaknesses:
                        cwe_data = weaknesses[0].get('description', [])
                        if cwe_data:
                            cwe_id = cwe_data[0].get('value')

                    cve_data = {
                        'cve_id': cve_id,
                        'cvss_score': cvss_score,
                        'cvss_severity': cvss_severity,
                        'description': description[:500],  # Truncate
                        'cwe_id': cwe_id,
                        'exploit_available': False  # Would need additional check
                    }

                    cves.append(cve_data)

                    # Store in cache
                    self.cache.store_cve(service_name, version, cve_data)

                logging.info(f"Found {len(cves)} CVEs for {service_name} {version}")
                return cves

            elif response.status_code == 404:
                logging.debug(f"No CVEs found for {service_name} {version}")
                return []
            else:
                logging.warning(f"NVD API returned status {response.status_code}")
                return []

        except Exception as e:
            logging.error(f"Error querying NVD API: {e}")
            return []

    @retry_with_backoff(max_retries=3, base_delay=1)
    def _make_circl_request(self, url: str, timeout: int):
        """Make CIRCL API request with retry logic"""
        return requests.get(url, timeout=timeout)

    def query_circl_api(self, service_name: str, version: str) -> List[Dict]:
        """Query CIRCL CVE Search API as backup"""
        api_config = self.config.get('apis', {}).get('circl', {})

        if not api_config.get('enabled', True):
            return []

        logging.info(f"Querying CIRCL for {service_name} {version}")

        self.circl_limiter.wait_if_needed()
        time.sleep(self.global_delay)

        try:
            # CIRCL search endpoint
            search_term = f"{service_name} {version}"
            url = f"{api_config['base_url']}/search/{quote(search_term)}"

            response = self._make_circl_request(url, api_config.get('timeout', 20))

            if response.status_code == 200:
                data = response.json()
                cves = []

                # CIRCL returns list of CVE objects
                for cve_item in data.get('results', []):
                    cve_id = cve_item.get('id')
                    cvss_score = cve_item.get('cvss')

                    # Determine severity from CVSS
                    severity_thresholds = self.config.get('severity', {})
                    if cvss_score >= severity_thresholds.get('critical', 9.0):
                        cvss_severity = 'CRITICAL'
                    elif cvss_score >= severity_thresholds.get('high', 7.0):
                        cvss_severity = 'HIGH'
                    elif cvss_score >= severity_thresholds.get('medium', 4.0):
                        cvss_severity = 'MEDIUM'
                    else:
                        cvss_severity = 'LOW'

                    cve_data = {
                        'cve_id': cve_id,
                        'cvss_score': cvss_score,
                        'cvss_severity': cvss_severity,
                        'description': cve_item.get('summary', 'No description')[:500],
                        'cwe_id': None,
                        'exploit_available': False
                    }

                    cves.append(cve_data)

                logging.info(f"CIRCL found {len(cves)} CVEs")
                return cves
            else:
                return []

        except Exception as e:
            logging.error(f"Error querying CIRCL API: {e}")
            return []

    @retry_with_backoff(max_retries=3, base_delay=1)
    def _make_mitre_request(self, url: str, timeout: int):
        """Make MITRE ATT&CK STIX request with retry logic"""
        return requests.get(url, timeout=timeout)

    def load_mitre_attack_data(self) -> Dict:
        """Load MITRE ATT&CK STIX data (cached locally)"""
        if self.mitre_data:
            return self.mitre_data

        api_config = self.config.get('apis', {}).get('mitre_attack', {})

        if not api_config.get('enabled', True):
            return {}

        cache_path = api_config.get('cache_path', 'cache/mitre_attack.json')
        cache_ttl = api_config.get('cache_ttl', 604800)

        # Check if cached file exists and is recent
        if os.path.exists(cache_path):
            file_age = time.time() - os.path.getmtime(cache_path)
            if file_age < cache_ttl:
                logging.info("Loading MITRE ATT&CK data from cache")
                with open(cache_path, 'r') as f:
                    self.mitre_data = json.load(f)
                return self.mitre_data

        # Download fresh data
        logging.info("Downloading MITRE ATT&CK STIX data")
        try:
            response = self._make_mitre_request(api_config['stix_url'], 60)
            if response.status_code == 200:
                self.mitre_data = response.json()

                # Cache it
                os.makedirs(os.path.dirname(cache_path), exist_ok=True)
                with open(cache_path, 'w') as f:
                    json.dump(self.mitre_data, f, indent=2)

                logging.info("MITRE ATT&CK data downloaded and cached")
                return self.mitre_data
        except Exception as e:
            logging.error(f"Error downloading MITRE data: {e}")

        return {}

    def map_cve_to_mitre(self, cve_data: Dict) -> List[Dict]:
        """Map CVE to MITRE ATT&CK techniques"""
        cve_id = cve_data.get('cve_id')
        description = cve_data.get('description', '').lower()
        cwe_id = cve_data.get('cwe_id', '')

        # Check cache first
        cached_techniques = self.cache.get_mitre_techniques(cve_id)
        if cached_techniques:
            return cached_techniques

        techniques = []

        # Use rule-based mapping from config
        mitre_mappings = self.config.get('mitre_mappings', {})

        for attack_type, mapping in mitre_mappings.items():
            if attack_type.lower() in description:
                for technique_id in mapping.get('techniques', []):
                    technique_data = {
                        'technique_id': technique_id,
                        'technique_name': attack_type,
                        'tactic': 'Multiple',  # Would need MITRE data lookup for exact tactic
                        'confidence': 'medium'
                    }
                    techniques.append(technique_data)

                    # Store in cache
                    self.cache.store_mitre_technique(cve_id, technique_data)

        # If no mapping found, try to infer from CVSS and description
        if not techniques:
            # Default to T1190 for network services
            if cve_data.get('cvss_score', 0) >= 7.0:
                technique_data = {
                    'technique_id': 'T1190',
                    'technique_name': 'Exploit Public-Facing Application',
                    'tactic': 'Initial Access',
                    'confidence': 'low'
                }
                techniques.append(technique_data)
                self.cache.store_mitre_technique(cve_id, technique_data)

        return techniques

    def process_tech_detection(self, input_dir: str) -> Dict[str, List[Dict]]:
        """Process tech_detection_unified.json"""
        tech_file = os.path.join(input_dir, 'tech_detection_unified.json')

        if not os.path.exists(tech_file):
            logging.warning(f"Tech detection file not found: {tech_file}")
            return {}

        logging.info(f"Processing tech detection file: {tech_file}")

        with open(tech_file, 'r') as f:
            tech_data = json.load(f)

        enriched_data = {}

        # Handle both dict and list formats
        if isinstance(tech_data, list):
            # New format: list of objects with "target", "server_tech", "client_tech"
            for item in tech_data:
                asset = item.get('target', 'unknown')
                asset_cves = []

                # Merge server_tech and client_tech into single dict
                technologies = {}
                if 'server_tech' in item and item['server_tech']:
                    technologies.update(item['server_tech'])
                if 'client_tech' in item and item['client_tech']:
                    technologies.update(item['client_tech'])

                if not technologies:
                    continue

                # Extract service versions
                services = self.extract_service_version(None, technologies)

                for service_name, version in services:
                    # Query for CVEs
                    cves = self.query_nvd_api(service_name, version)

                    # Fallback to CIRCL if NVD returns nothing
                    if not cves:
                        cves = self.query_circl_api(service_name, version)

                    # Map to MITRE
                    for cve in cves:
                        cve['service'] = service_name
                        cve['version'] = version
                        cve['mitre_techniques'] = self.map_cve_to_mitre(cve)
                        asset_cves.append(cve)

                if asset_cves:
                    enriched_data[asset] = asset_cves

        elif isinstance(tech_data, dict):
            # Old format: dict with asset keys mapping to technologies
            for asset, technologies in tech_data.items():
                asset_cves = []

                # Extract service versions
                services = self.extract_service_version(None, technologies)

                for service_name, version in services:
                    # Query for CVEs
                    cves = self.query_nvd_api(service_name, version)

                    # Fallback to CIRCL if NVD returns nothing
                    if not cves:
                        cves = self.query_circl_api(service_name, version)

                    # Map to MITRE
                    for cve in cves:
                        cve['service'] = service_name
                        cve['version'] = version
                        cve['mitre_techniques'] = self.map_cve_to_mitre(cve)
                        asset_cves.append(cve)

                if asset_cves:
                    enriched_data[asset] = asset_cves
        else:
            logging.error(f"Unexpected tech_data format: {type(tech_data)}")
            return {}

        return enriched_data

    def process_open_ports(self, input_dir: str) -> Dict[str, List[Dict]]:
        """Process Open_Ports_1_out.csv"""
        ports_file = os.path.join(input_dir, 'Open_Ports_1_out.csv')

        if not os.path.exists(ports_file):
            logging.warning(f"Open ports file not found: {ports_file}")
            return {}

        logging.info(f"Processing open ports file: {ports_file}")

        enriched_data = {}

        with open(ports_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                domain = row.get('domain')
                port = row.get('port')
                banner = row.get('banner', '')

                if not domain or not port:
                    continue

                asset_key = f"{domain}:{port}"
                asset_findings = []

                # Check for risky ports
                risky_ports = self.config.get('risky_ports', {})
                if int(port) in risky_ports:
                    port_info = risky_ports[int(port)]
                    finding = {
                        'type': 'risky_port',
                        'port': port,
                        'service': port_info.get('service'),
                        'risk_level': port_info.get('risk'),
                        'reason': port_info.get('reason'),
                        'mitre_techniques': [
                            {'technique_id': tid} for tid in port_info.get('mitre_techniques', [])
                        ]
                    }
                    asset_findings.append(finding)

                # Extract service version from banner
                if banner:
                    services = self.extract_service_version(banner)

                    for service_name, version in services:
                        cves = self.query_nvd_api(service_name, version)

                        for cve in cves:
                            cve['service'] = service_name
                            cve['version'] = version
                            cve['port'] = port
                            cve['mitre_techniques'] = self.map_cve_to_mitre(cve)
                            asset_findings.append(cve)

                if asset_findings:
                    enriched_data[asset_key] = asset_findings

        return enriched_data

    def process_ssl_tls(self, input_dir: str) -> Dict[str, List[Dict]]:
        """Process SSL_TLS_Cert_Check_out.csv"""
        ssl_file = os.path.join(input_dir, 'SSL_TLS_Cert_Check_out.csv')

        if not os.path.exists(ssl_file):
            logging.warning(f"SSL/TLS file not found: {ssl_file}")
            return {}

        logging.info(f"Processing SSL/TLS file: {ssl_file}")

        enriched_data = {}
        ssl_vulns = self.config.get('ssl_vulnerabilities', {})

        with open(ssl_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                domain = row.get('domain')
                status = row.get('status', '')

                if not domain:
                    continue

                findings = []

                # Check for SSL/TLS issues in status
                for ssl_version, vuln_info in ssl_vulns.items():
                    if ssl_version.lower() in status.lower():
                        finding = {
                            'type': 'ssl_vulnerability',
                            'ssl_version': ssl_version,
                            'cve_id': vuln_info.get('cve'),
                            'cvss_severity': vuln_info.get('severity'),
                            'description': vuln_info.get('description'),
                            'mitre_techniques': [
                                {'technique_id': tid} for tid in vuln_info.get('mitre_techniques', [])
                            ]
                        }
                        findings.append(finding)

                # Check for certificate errors
                if 'CERTIFICATE_VERIFY_FAILED' in status or 'expired' in status.lower():
                    finding = {
                        'type': 'certificate_issue',
                        'issue': status,
                        'risk_level': 'MEDIUM',
                        'description': 'Certificate validation failure or expiration',
                        'mitre_techniques': [{'technique_id': 'T1557.001'}]  # MITM
                    }
                    findings.append(finding)

                if findings:
                    enriched_data[domain] = findings

        return enriched_data

    def generate_remediation_guidance(self, cve_data: Dict) -> Dict:
        """Generate remediation guidance for a CVE"""
        severity = cve_data.get('cvss_severity', 'UNKNOWN').upper()

        remediation_templates = self.config.get('remediation', {})

        if severity == 'CRITICAL':
            template = remediation_templates.get('critical', remediation_templates.get('default', {}))
        else:
            template = remediation_templates.get('default', {})

        return {
            'cve_id': cve_data.get('cve_id'),
            'priority': template.get('priority'),
            'actions': template.get('actions', []),
            'severity': severity,
            'cvss_score': cve_data.get('cvss_score')
        }

    def enrich(self, input_dir: str, output_dir: str):
        """Main enrichment workflow"""
        logging.info(f"Starting threat context enrichment")
        logging.info(f"Input directory: {input_dir}")
        logging.info(f"Output directory: {output_dir}")

        os.makedirs(output_dir, exist_ok=True)

        # Process all input sources
        tech_enriched = self.process_tech_detection(input_dir)
        ports_enriched = self.process_open_ports(input_dir)
        ssl_enriched = self.process_ssl_tls(input_dir)

        # Combine all findings
        all_findings = {}

        for asset, findings in tech_enriched.items():
            all_findings[asset] = all_findings.get(asset, []) + findings

        for asset, findings in ports_enriched.items():
            all_findings[asset] = all_findings.get(asset, []) + findings

        for asset, findings in ssl_enriched.items():
            all_findings[asset] = all_findings.get(asset, []) + findings

        # Generate outputs
        self._write_threat_context_json(all_findings, output_dir)
        self._write_threat_context_csv(all_findings, output_dir)
        self._write_high_risk_assets(all_findings, output_dir)
        self._write_remediation_guidance(all_findings, output_dir)

        logging.info("Threat context enrichment completed")

    def _write_threat_context_json(self, findings: Dict, output_dir: str):
        """Write threat_context.json"""
        output_file = os.path.join(output_dir, 'threat_context.json')

        output_data = {
            'metadata': {
                'generated_at': datetime.now(timezone.utc).strftime(
                    self.config.get('output', {}).get('timestamp_format', '%Y-%m-%d %H:%M:%S UTC')
                ),
                'total_assets': len(findings),
                'total_findings': sum(len(f) for f in findings.values())
            },
            'assets': findings
        }

        with open(output_file, 'w') as f:
            json.dump(
                output_data,
                f,
                indent=self.config.get('output', {}).get('json_indent', 2)
            )

        logging.info(f"Wrote {output_file}")

    def _write_threat_context_csv(self, findings: Dict, output_dir: str):
        """Write threat_context_summary.csv"""
        output_file = os.path.join(output_dir, 'threat_context_summary.csv')

        with open(output_file, 'w', newline='') as f:
            fieldnames = [
                'asset', 'service', 'version', 'port', 'cve_id',
                'cvss_score', 'severity', 'mitre_technique', 'description'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for asset, asset_findings in findings.items():
                for finding in asset_findings:
                    # Handle different finding types
                    mitre_techniques = ', '.join([
                        t.get('technique_id', '') for t in finding.get('mitre_techniques', [])
                    ])

                    row = {
                        'asset': asset,
                        'service': finding.get('service', finding.get('type', 'N/A')),
                        'version': finding.get('version', 'N/A'),
                        'port': finding.get('port', 'N/A'),
                        'cve_id': finding.get('cve_id', 'N/A'),
                        'cvss_score': finding.get('cvss_score', 'N/A'),
                        'severity': finding.get('cvss_severity', finding.get('risk_level', 'N/A')),
                        'mitre_technique': mitre_techniques,
                        'description': (finding.get('description', finding.get('reason', '')) or '')[:200]
                    }
                    writer.writerow(row)

        logging.info(f"Wrote {output_file}")

    def _write_high_risk_assets(self, findings: Dict, output_dir: str):
        """Write high_risk_assets.txt (CVSS >= 7.0)"""
        output_file = os.path.join(output_dir, 'high_risk_assets.txt')

        high_risk = set()
        threshold = self.config.get('severity', {}).get('high', 7.0)

        for asset, asset_findings in findings.items():
            for finding in asset_findings:
                cvss_score = finding.get('cvss_score')
                if cvss_score and cvss_score >= threshold:
                    high_risk.add(asset)
                    break

        with open(output_file, 'w') as f:
            for asset in sorted(high_risk):
                f.write(f"{asset}\n")

        logging.info(f"Wrote {output_file} ({len(high_risk)} high-risk assets)")

    def _write_remediation_guidance(self, findings: Dict, output_dir: str):
        """Write remediation_guidance.json"""
        output_file = os.path.join(output_dir, 'remediation_guidance.json')

        remediation_map = {}

        for asset, asset_findings in findings.items():
            for finding in asset_findings:
                if finding.get('cve_id'):
                    cve_id = finding['cve_id']
                    if cve_id not in remediation_map:
                        remediation_map[cve_id] = self.generate_remediation_guidance(finding)
                        remediation_map[cve_id]['affected_assets'] = []

                    remediation_map[cve_id]['affected_assets'].append(asset)

        with open(output_file, 'w') as f:
            json.dump(remediation_map, f, indent=2)

        logging.info(f"Wrote {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Threat Context Enrichment - Maps services/technologies to CVEs and MITRE ATT&CK'
    )
    parser.add_argument(
        '--input-dir',
        default='raw_outputs',
        help='Input directory containing tech_detection_unified.json, Open_Ports_1_out.csv, etc.'
    )
    parser.add_argument(
        '--output-dir',
        default='threat_context',
        help='Output directory for enriched threat context'
    )
    parser.add_argument(
        '--config',
        default='config/threat_intel.yml',
        help='Path to threat intelligence config file'
    )
    parser.add_argument(
        '--env-config',
        help='Path to environment config file (optional)'
    )
    parser.add_argument(
        '--cleanup-cache',
        action='store_true',
        help='Clean up old cache entries before running'
    )

    args = parser.parse_args()

    try:
        enricher = ThreatContextEnricher(args.config, args.env_config)

        if args.cleanup_cache:
            deleted = enricher.cache.cleanup_old_entries()
            logging.info(f"Cleaned up {deleted} old cache entries")

        enricher.enrich(args.input_dir, args.output_dir)

        print("\nThreat Context Enrichment Complete!")
        print(f"Results written to: {args.output_dir}")

    except Exception as e:
        logging.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
