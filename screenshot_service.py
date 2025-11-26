#!/usr/bin/env python3
"""
Unified Screenshot Service
Consolidates ScreenShotterQuiet, screenshot_websites, and unified_screenshotter
into a single, modern, config-driven screenshot capture tool.

Features:
- Multi-port support (80, 443, 8080, 8443, custom)
- Headless Chrome with Selenium
- Threaded concurrent execution with configurable limits
- Quiet/minimal output mode
- Config-driven settings (threads, timeout, window size, dev mode caps)
- Metadata JSON output alongside screenshots
- HTML report generation with categorization
- Progress tracking with optional quiet mode
"""

import logging
import argparse
import sys
from typing import Dict, List, Tuple
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import urllib3
from urllib.parse import urlparse
from threading import Semaphore, Lock
from datetime import datetime
import yaml

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from webdriver_manager.chrome import ChromeDriverManager
    WEBDRIVER_MANAGER_AVAILABLE = True
except ImportError:
    WEBDRIVER_MANAGER_AVAILABLE = False
    logging.warning("webdriver-manager not available, using system chromedriver")


class ConfigManager:
    """Load and manage configuration from YAML file."""

    DEFAULT_CONFIG = {
        'threads': 5,
        'timeout': 10,
        'page_load_timeout': 15,
        'window_width': 1280,
        'window_height': 800,
        'browser_limit': 3,
        'quiet': False,
        'generate_html_report': True,
        'output_dir': './screenshots_output',
        'ports': [80, 443, 8080, 8443],
        'user_agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'dev_mode': False,
    }

    def __init__(self, config_file: str = None):
        self.config = self.DEFAULT_CONFIG.copy()
        if config_file and os.path.exists(config_file):
            self.load_from_file(config_file)
        self._validate_config()

    def load_from_file(self, config_file: str):
        """Load configuration from YAML file."""
        try:
            with open(config_file, 'r') as f:
                loaded = yaml.safe_load(f) or {}
                self.config.update(loaded)
        except Exception as e:
            logging.warning(f"Failed to load config file {config_file}: {e}")

    def _validate_config(self):
        """Validate and ensure required config values."""
        self.config['threads'] = max(1, min(self.config.get('threads', 5), 20))
        self.config['timeout'] = max(1, self.config.get('timeout', 10))
        self.config['page_load_timeout'] = max(1, self.config.get('page_load_timeout', 15))
        self.config['browser_limit'] = max(1, self.config.get('browser_limit', 3))
        self.config['window_width'] = max(800, self.config.get('window_width', 1280))
        self.config['window_height'] = max(600, self.config.get('window_height', 800))

    def get(self, key: str, default=None):
        """Get configuration value."""
        return self.config.get(key, default)

    def __getitem__(self, key):
        return self.config[key]


class ChromeDriverPool:
    """Pool of Chrome driver instances with semaphore limit."""

    def __init__(self, pool_size: int, config: ConfigManager):
        self.config = config
        self.pool_size = pool_size
        self.semaphore = Semaphore(pool_size)
        self.drivers = {}
        self.lock = Lock()
        self._driver_creation_failed = False
        self._driver_error_msg = None

    def test_driver_creation(self) -> Tuple[bool, str]:
        """Test if we can create a driver successfully."""
        try:
            driver = self._create_driver()
            driver.quit()
            return True, "Driver test successful"
        except Exception as e:
            self._driver_creation_failed = True
            self._driver_error_msg = str(e)
            return False, str(e)

    def acquire(self) -> webdriver.Chrome:
        """Acquire a driver instance."""
        self.semaphore.acquire()
        return self._create_driver()

    def release(self, driver: webdriver.Chrome):
        """Release a driver instance."""
        if driver:
            try:
                driver.quit()
            except:
                pass
        self.semaphore.release()

    def _create_driver(self) -> webdriver.Chrome:
        """Create a new Chrome driver with headless options and automatic driver management."""
        import tempfile
        options = Options()
        options.add_argument('--headless=new')  # Use new headless mode for better WSL compatibility
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-gpu')
        options.add_argument('--log-level=3')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-setuid-sandbox')  # WSL compatibility
        options.add_argument('--disable-software-rasterizer')  # WSL compatibility
        options.add_argument('--disable-extensions')  # Reduce overhead
        options.add_argument('--remote-debugging-port=9222')  # Required for WSL
        options.add_argument('--disable-blink-features=AutomationControlled')
        options.add_argument('--ignore-certificate-errors')
        options.add_experimental_option('excludeSwitches', ['enable-automation'])
        options.add_experimental_option('useAutomationExtension', False)

        # Create temporary profile directory for each session (WSL compatibility)
        temp_dir = tempfile.mkdtemp(prefix='chrome_profile_')
        options.add_argument(f'--user-data-dir={temp_dir}')

        window_w = self.config['window_width']
        window_h = self.config['window_height']
        options.add_argument(f'--window-size={window_w},{window_h}')

        if self.config.get('user_agent'):
            options.add_argument(f'user-agent={self.config["user_agent"]}')

        driver = None
        last_error = None

        # Strategy 1: Try local chromedriver_142 (version-matched with Chromium 142)
        try:
            local_driver_path = os.path.join(os.path.dirname(__file__), 'chromedriver_142')
            if os.path.exists(local_driver_path):
                service = Service(local_driver_path)
                driver = webdriver.Chrome(service=service, options=options)
                driver.set_page_load_timeout(self.config['page_load_timeout'])
                driver.implicitly_wait(3)
                return driver
        except Exception as e:
            last_error = e
            logging.debug(f"Local chromedriver_142 failed: {e}")

        # Strategy 2: Try local chromedriver_141 (fallback)
        try:
            local_driver_path = os.path.join(os.path.dirname(__file__), 'chromedriver_141')
            if os.path.exists(local_driver_path):
                service = Service(local_driver_path)
                driver = webdriver.Chrome(service=service, options=options)
                driver.set_page_load_timeout(self.config['page_load_timeout'])
                driver.implicitly_wait(3)
                return driver
        except Exception as e:
            last_error = e
            logging.debug(f"Local chromedriver_141 failed: {e}")

        # Strategy 3: Try webdriver-manager (automatic driver management) - last resort due to potential hangs
        if WEBDRIVER_MANAGER_AVAILABLE:
            try:
                service = Service(ChromeDriverManager().install())
                driver = webdriver.Chrome(service=service, options=options)
                driver.set_page_load_timeout(self.config['page_load_timeout'])
                driver.implicitly_wait(3)
                return driver
            except Exception as e:
                last_error = e
                logging.debug(f"webdriver-manager failed: {e}, trying fallback...")

        # Strategy 4: Try system chromedriver
        try:
            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(self.config['page_load_timeout'])
            driver.implicitly_wait(3)
            return driver
        except Exception as e:
            last_error = e
            logging.debug(f"System chromedriver failed: {e}")

        # Strategy 5: Try specifying chromedriver path explicitly
        try:
            service = Service('/usr/bin/chromedriver')
            driver = webdriver.Chrome(service=service, options=options)
            driver.set_page_load_timeout(self.config['page_load_timeout'])
            driver.implicitly_wait(3)
            return driver
        except Exception as e:
            last_error = e

        # All strategies failed
        raise RuntimeError(f"Failed to create Chrome driver after all strategies. Last error: {last_error}")


class InputLoader:
    """Load URLs/domains from various input formats."""

    @staticmethod
    def load_domains_from_csv(input_file: str) -> List[str]:
        """Load domains from CSV file with 'domain' column."""
        domains = []
        try:
            with open(input_file, newline='') as f:
                reader = csv.reader(f)
                header = next(reader, None)

                if not header:
                    return domains

                # Find domain column (case-insensitive)
                domain_idx = -1
                for i, col in enumerate(header):
                    if col.lower().strip() == 'domain':
                        domain_idx = i
                        break

                if domain_idx == -1:
                    logging.warning("'domain' column not found in CSV, using first column")
                    domain_idx = 0

                for row in reader:
                    if row and len(row) > domain_idx and row[domain_idx].strip():
                        domains.append(row[domain_idx].strip())

        except FileNotFoundError:
            logging.error(f"Input file not found: {input_file}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Error reading CSV file: {e}")
            sys.exit(1)

        return domains

    @staticmethod
    def load_urls_from_file(input_file: str) -> List[str]:
        """Load URLs from plain text file (one per line)."""
        urls = []
        try:
            with open(input_file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logging.error(f"Input file not found: {input_file}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Error reading file: {e}")
            sys.exit(1)

        return urls

    @staticmethod
    def load_input(input_file: str, format_type: str = 'auto') -> List[str]:
        """Auto-detect or load input based on format."""
        if format_type == 'csv' or (format_type == 'auto' and input_file.endswith('.csv')):
            return InputLoader.load_domains_from_csv(input_file)
        else:
            return InputLoader.load_urls_from_file(input_file)


class MetadataCollector:
    """Collect and store screenshot metadata."""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.metadata = {}
        self.lock = Lock()

    def add_entry(self, url: str, filename: str, status: int = None,
                  success: bool = False, error: str = None, **kwargs):
        """Add metadata entry for a screenshot."""
        with self.lock:
            entry = {
                'url': url,
                'filename': filename,
                'timestamp': datetime.now().isoformat(),
                'success': success,
            }
            if status:
                entry['status_code'] = status
            if error:
                entry['error'] = error
            entry.update(kwargs)

            safe_key = url.replace('://', '_').replace(':', '_').replace('/', '_')
            self.metadata[safe_key] = entry

    def save(self, filename: str = 'metadata.json'):
        """Save metadata to JSON file."""
        try:
            filepath = os.path.join(self.output_dir, filename)
            with open(filepath, 'w') as f:
                json.dump(self.metadata, f, indent=2)
            return filepath
        except Exception as e:
            logging.error(f"Failed to save metadata: {e}")


class ScreenshotTaker:
    """Core screenshot capture functionality."""

    # Keywords for categorizing results
    DEV_KEYWORDS = [
        'dev', 'stage', 'test', 'tst', 'uat', 'stg', 'staging',
        'nonprod', 'nonprd', 'sit', 'sandbox', 'preprd', 'preprod'
    ]

    def __init__(self, driver_pool: ChromeDriverPool, config: ConfigManager,
                 screenshots_dir: str, quiet: bool = False):
        self.driver_pool = driver_pool
        self.config = config
        self.screenshots_dir = screenshots_dir
        self.quiet = quiet
        self.lock = Lock()
        self.results = {
            'login_pages': [],
            'test_staging': [],
            'status_errors': [],
            'others': [],
            'failed': []
        }

    def capture_screenshot(self, url: str, filepath: str, max_retries: int = 2) -> bool:
        """Capture a single screenshot using Selenium with retry logic."""
        for attempt in range(max_retries):
            driver = None
            try:
                driver = self.driver_pool.acquire()

                # Set timeouts
                driver.set_page_load_timeout(self.config['page_load_timeout'])

                # Navigate to URL
                driver.get(url)

                # Wait for body element to load
                WebDriverWait(driver, self.config['timeout']).until(
                    EC.presence_of_element_located((By.TAG_NAME, 'body'))
                )

                # Small delay for rendering
                time.sleep(0.5)

                # Save screenshot
                driver.save_screenshot(filepath)

                if not self.quiet:
                    logging.info(f"Screenshot saved: {filepath}")

                return True

            except Exception as e:
                error_msg = str(e)[:200]

                # Don't retry on certain errors
                if 'This version of ChromeDriver only supports' in error_msg:
                    if not self.quiet:
                        logging.warning(f"ChromeDriver version mismatch for {url}, skipping retries")
                    return False

                if attempt < max_retries - 1:
                    if not self.quiet:
                        logging.debug(f"Retry {attempt + 1}/{max_retries} for {url}: {error_msg}")
                    time.sleep(1)  # Brief delay before retry
                else:
                    if not self.quiet:
                        logging.warning(f"Failed to capture {url} after {max_retries} attempts: {error_msg}")
                    return False

            finally:
                if driver:
                    self.driver_pool.release(driver)

        return False

    def categorize_result(self, url: str, status: int = 200, has_login: bool = False) -> str:
        """Categorize result based on URL and status."""
        if has_login:
            return 'login_pages'
        if status in [401, 403] or status >= 500:
            return 'status_errors'
        if any(keyword in url.lower() for keyword in self.DEV_KEYWORDS):
            return 'test_staging'
        return 'others'

    def process_url(self, url: str, port: int, protocol: str) -> Dict:
        """Process a single URL with given port and protocol."""
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname if parsed_url.hostname else url
        
        full_url = f"{protocol}://{hostname}:{port}"

        # Create safe filename
        safe_domain = hostname.replace('://', '_').replace(':', '_').replace('/', '_')
        filename = f"{safe_domain}_{port}_{protocol}.png"
        filepath = os.path.join(self.screenshots_dir, filename)

        result = {
            'url': full_url,
            'filename': filename,
            'protocol': protocol,
            'port': port,
            'success': False,
            'category': None
        }

        try:
            success = self.capture_screenshot(full_url, filepath)

            if success:
                result['success'] = True
                # Simplified categorization (would need BeautifulSoup for better detection)
                result['category'] = self.categorize_result(full_url)

                with self.lock:
                    self.results[result['category']].append(result)
            else:
                with self.lock:
                    self.results['failed'].append(result)

        except Exception as e:
            result['error'] = str(e)
            with self.lock:
                self.results['failed'].append(result)

        return result


class ScreenshotService:
    """Main screenshot service orchestrator."""

    def __init__(self, config_file: str = None):
        self.config = ConfigManager(config_file)
        self.setup_logging()
        self.driver_pool = ChromeDriverPool(self.config['browser_limit'], self.config)
        self.screenshot_taker = None
        self.metadata_collector = None

    def setup_logging(self):
        """Configure logging based on quiet mode."""
        level = logging.WARNING if self.config['quiet'] else logging.INFO
        logging.basicConfig(
            level=level,
            format='[%(levelname)s] %(message)s'
        )

    def process_targets(self, input_file: str, ports: List[int] = None,
                       output_dir: str = None, input_format: str = 'auto') -> Dict:
        """Process all targets and generate screenshots."""

        # Setup directories
        output_dir = output_dir or self.config['output_dir']
        screenshots_dir = os.path.join(output_dir, 'screenshots')
        os.makedirs(screenshots_dir, exist_ok=True)

        # Test driver creation before proceeding
        logging.info("Testing Chrome driver creation...")
        driver_ok, driver_msg = self.driver_pool.test_driver_creation()
        if not driver_ok:
            logging.error(f"Chrome driver test failed: {driver_msg}")
            logging.error("Please ensure Chrome and ChromeDriver versions are compatible")
            logging.warning("Attempting to continue with automatic driver management...")

        # Load input
        logging.info(f"Loading targets from {input_file}")
        targets = InputLoader.load_input(input_file, input_format)

        if not targets:
            logging.error("No targets loaded from input file")
            return {'error': 'No targets loaded'}

        logging.info(f"Loaded {len(targets)} targets")

        # Setup ports
        ports = ports or self.config['ports']

        # Initialize components
        self.screenshot_taker = ScreenshotTaker(
            self.driver_pool,
            self.config,
            screenshots_dir,
            quiet=self.config['quiet']
        )
        self.metadata_collector = MetadataCollector(output_dir)

        # Process targets
        total_tasks = len(targets) * len(ports) * 2  # Each port has http and https
        completed = 0

        with ThreadPoolExecutor(max_workers=self.config['threads']) as executor:
            futures = {}

            for target in targets:
                for port in ports:
                    for protocol in ['http', 'https']:
                        future = executor.submit(
                            self.screenshot_taker.process_url,
                            target, port, protocol
                        )
                        futures[future] = (target, port, protocol)

            # Collect results
            for future in as_completed(futures):
                completed += 1
                target, port, protocol = futures[future]

                try:
                    result = future.result()
                    self.metadata_collector.add_entry(
                        result['url'],
                        result['filename'],
                        success=result['success'],
                        category=result.get('category'),
                        error=result.get('error')
                    )
                except Exception as e:
                    logging.error(f"Error processing {target}:{port}/{protocol}: {e}")

                if not self.config['quiet'] and completed % 10 == 0:
                    pct = (completed / len(futures)) * 100
                    logging.info(f"Progress: {pct:.1f}% ({completed}/{len(futures)})")

        # Save results
        metadata_file = self.metadata_collector.save()
        logging.info(f"Metadata saved to {metadata_file}")

        # Generate reports
        if self.config['generate_html_report']:
            self.generate_html_report(output_dir, screenshots_dir)

        self.save_csv_report(output_dir)

        return {
            'output_dir': output_dir,
            'screenshots_dir': screenshots_dir,
            'metadata_file': metadata_file,
            'results': self.screenshot_taker.results,
            'total_targets': len(targets),
            'total_requests': completed
        }

    def generate_html_report(self, output_dir: str, screenshots_dir: str):
        """Generate HTML report of screenshots."""
        try:
            results = self.screenshot_taker.results

            category_titles = {
                'login_pages': 'Websites with Login Pages',
                'test_staging': 'Test and Staging Websites',
                'status_errors': 'Websites with Error Status (401, 403, 50x)',
                'others': 'Other Websites',
                'failed': 'Failed Captures'
            }

            categories_html = ""

            for category, pages in results.items():
                if not pages:
                    continue

                items_html = ""
                for page in pages:
                    filepath = os.path.join(screenshots_dir, page['filename'])

                    if os.path.exists(filepath):
                        with open(filepath, 'rb') as f:
                            import base64
                            img_data = base64.b64encode(f.read()).decode('utf-8')

                        items_html += f"""
                        <div style="margin-bottom: 20px; padding: 10px; border: 1px solid #ddd;">
                            <p><strong>{page['url']}</strong></p>
                            <img src="data:image/png;base64,{img_data}" style="max-width: 400px; border: 1px solid #ccc;">
                            <p><small>File: {page['filename']}</small></p>
                        </div>
                        """
                    else:
                        items_html += f"""
                        <div style="margin-bottom: 20px; padding: 10px; border: 1px solid #ddd;">
                            <p><strong>{page['url']}</strong> - Screenshot file not found</p>
                        </div>
                        """

                if items_html:
                    categories_html += f"""
                    <div style="margin: 20px 0;">
                        <h2>{category_titles.get(category, category)}</h2>
                        {items_html}
                    </div>
                    """

            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Screenshot Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1 {{ color: #333; }}
                    h2 {{ color: #666; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
                    img {{ max-width: 100%; height: auto; }}
                    .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                </style>
            </head>
            <body>
                <h1>Screenshot Report</h1>
                <div class="summary">
                    <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p><strong>Total Screenshots:</strong> {sum(len(v) for v in results.values())}</p>
                </div>
                {categories_html}
            </body>
            </html>
            """

            report_file = os.path.join(output_dir, 'report.html')
            with open(report_file, 'w') as f:
                f.write(html_content)

            logging.info(f"HTML report generated: {report_file}")

        except Exception as e:
            logging.error(f"Failed to generate HTML report: {e}")

    def save_csv_report(self, output_dir: str):
        """Save results as CSV file."""
        try:
            results = self.screenshot_taker.results
            rows = []

            for category, pages in results.items():
                for page in pages:
                    rows.append({
                        'url': page['url'],
                        'filename': page['filename'],
                        'category': category,
                        'success': page.get('success', False),
                        'error': page.get('error', '')
                    })

            csv_file = os.path.join(output_dir, 'screenshot_results.csv')
            if rows:
                with open(csv_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                    writer.writeheader()
                    writer.writerows(rows)

                logging.info(f"CSV report saved: {csv_file}")

        except Exception as e:
            logging.error(f"Failed to save CSV report: {e}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Unified Screenshot Service - Capture website screenshots with flexible configuration'
    )
    parser.add_argument('-i', '--input', required=True,
                       help='Input file (CSV with domain column or plain text URLs)')
    parser.add_argument('-o', '--output',
                       help='Output directory (default: ./screenshots_output)')
    parser.add_argument('-c', '--config',
                       help='Config YAML file (default: config/screenshots.yml)')
    parser.add_argument('-p', '--ports',
                       help='Comma-separated ports (default: 80,443,8080,8443)')
    parser.add_argument('-t', '--threads', type=int,
                       help='Number of threads')
    parser.add_argument('-f', '--format', choices=['csv', 'text', 'auto'], default='auto',
                       help='Input format (default: auto-detect)')
    parser.add_argument('--quiet', action='store_true',
                       help='Quiet mode (minimal output)')
    parser.add_argument('--no-html', action='store_true',
                       help='Skip HTML report generation')

    args = parser.parse_args()

    # Determine config file
    config_file = args.config
    if not config_file:
        default_config = os.path.join(
            os.path.dirname(__file__), 'config', 'screenshots.yml'
        )
        if os.path.exists(default_config):
            config_file = default_config

    # Create service
    service = ScreenshotService(config_file)

    # Override config with CLI args
    if args.threads:
        service.config.config['threads'] = args.threads
    if args.quiet:
        service.config.config['quiet'] = True
    if args.no_html:
        service.config.config['generate_html_report'] = False

    # Parse ports
    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            logging.error("Invalid port format")
            sys.exit(1)

    # Process targets
    try:
        result = service.process_targets(
            args.input,
            ports=ports,
            output_dir=args.output,
            input_format=args.format
        )

        if 'error' in result:
            logging.error(result['error'])
            sys.exit(1)

        logging.info(f"Screenshots saved to: {result['screenshots_dir']}")
        logging.info(f"Results: {result['results']}")

    except KeyboardInterrupt:
        logging.info("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
