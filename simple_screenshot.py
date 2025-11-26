#!/usr/bin/env python3
"""
Simple Screenshot Script
Takes a list of URLs and captures screenshots using headless Chrome.
Cross-platform compatible: Linux, macOS, Windows (including WSL).
"""
import os
import sys
import tempfile
import shutil
import argparse
import platform
from pathlib import Path
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service


def detect_platform():
    """Detect the operating system."""
    system = platform.system().lower()
    if system == 'linux':
        try:
            with open('/proc/version', 'r') as f:
                if 'microsoft' in f.read().lower():
                    return 'wsl'
        except:
            pass
        return 'linux'
    elif system == 'darwin':
        return 'macos'
    elif system == 'windows':
        return 'windows'
    return 'unknown'


def find_chrome_binary():
    """Find Chrome/Chromium binary path."""
    platform_name = detect_platform()

    if platform_name in ['linux', 'wsl']:
        candidates = [
            '/usr/bin/google-chrome',
            '/usr/bin/chromium-browser',
            '/usr/bin/chromium',
            '/snap/bin/chromium',
            shutil.which('google-chrome'),
            shutil.which('chromium-browser'),
            shutil.which('chromium')
        ]
    elif platform_name == 'macos':
        candidates = [
            '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
            '/Applications/Chromium.app/Contents/MacOS/Chromium',
            shutil.which('google-chrome'),
            shutil.which('chromium')
        ]
    elif platform_name == 'windows':
        candidates = [
            r'C:\Program Files\Google\Chrome\Application\chrome.exe',
            r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
            shutil.which('chrome'),
            shutil.which('google-chrome')
        ]
    else:
        return None

    for path in candidates:
        if path and Path(path).exists():
            return str(path)

    return None


def create_driver(chromedriver_path, window_width=1280, window_height=800):
    """Create a headless Chrome driver with cross-platform compatible options."""
    platform_name = detect_platform()

    options = Options()

    # Find Chrome binary
    chrome_binary = find_chrome_binary()
    if chrome_binary:
        options.binary_location = chrome_binary

    # Platform-specific options
    if platform_name in ['linux', 'wsl']:
        # WSL and Linux-specific options
        options.add_argument('--headless=new')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-gpu')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-setuid-sandbox')
        options.add_argument('--disable-software-rasterizer')
        options.add_argument('--remote-debugging-port=9222')
    elif platform_name == 'macos':
        # macOS-specific options
        options.add_argument('--headless=new')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-gpu')
    elif platform_name == 'windows':
        # Windows-specific options
        options.add_argument('--headless=new')
        options.add_argument('--disable-gpu')
    else:
        # Generic fallback
        options.add_argument('--headless=new')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-gpu')

    # Common options for all platforms
    options.add_argument('--log-level=3')
    options.add_argument('--disable-extensions')
    options.add_argument('--ignore-certificate-errors')
    options.add_argument(f'--window-size={window_width},{window_height}')

    # Create temporary profile directory (cross-platform)
    temp_dir = tempfile.mkdtemp(prefix='chrome_profile_')
    options.add_argument(f'--user-data-dir={temp_dir}')

    service = Service(str(chromedriver_path))
    driver = webdriver.Chrome(service=service, options=options)
    driver.set_page_load_timeout(15)
    driver.implicitly_wait(3)

    return driver, temp_dir


def get_safe_filename(url):
    """Generate safe filename from URL."""
    parsed = urlparse(url)
    hostname = parsed.hostname or 'unknown'
    path = parsed.path.replace('/', '_')
    filename = f"{parsed.scheme}_{hostname}{path}".replace(':', '_')
    # Clean up multiple underscores
    filename = '_'.join(filter(None, filename.split('_')))
    return f"{filename}.png"


def find_chromedriver():
    """Find ChromeDriver in common locations."""
    workspace = Path(__file__).parent
    platform_name = detect_platform()

    # Determine ChromeDriver filename
    chromedriver_name = 'chromedriver.exe' if platform_name == 'windows' else 'chromedriver'

    # Search locations (in order of preference)
    search_paths = [
        # Workspace chromedrivers (version-specific)
        workspace / 'chromedriver_142',
        workspace / 'chromedriver_142.exe',
        workspace / 'chromedriver_141',
        workspace / 'chromedriver_141.exe',
        workspace / 'chromedriver_140',
        workspace / 'chromedriver_140.exe',
        # Go bin directory
        Path.home() / 'go' / 'bin' / chromedriver_name,
        # System PATH
        shutil.which('chromedriver'),
        # Common system locations
        Path('/usr/local/bin') / chromedriver_name,
        Path('/usr/bin') / chromedriver_name,
    ]

    for path in search_paths:
        if path and Path(path).exists():
            return Path(path)

    return None


def main():
    parser = argparse.ArgumentParser(description='Capture screenshots of URLs')
    parser.add_argument('-i', '--input', required=True, help='Input file with URLs (one per line)')
    parser.add_argument('-o', '--output', required=True, help='Output directory for screenshots')
    parser.add_argument('-c', '--chromedriver', default=None,
                       help='Path to ChromeDriver binary (auto-detected if not specified)')
    parser.add_argument('-w', '--width', type=int, default=1280, help='Window width')
    parser.add_argument('-H', '--height', type=int, default=800, help='Window height')

    args = parser.parse_args()

    # Find or use specified ChromeDriver
    if args.chromedriver:
        chromedriver_path = Path(args.chromedriver)
        if not chromedriver_path.exists():
            print(f"ERROR: ChromeDriver not found: {args.chromedriver}", file=sys.stderr)
            sys.exit(1)
    else:
        chromedriver_path = find_chromedriver()
        if not chromedriver_path:
            print("ERROR: ChromeDriver not found.", file=sys.stderr)
            print("\nPlease either:", file=sys.stderr)
            print("  1. Run: python3 utils/dependency_manager.py", file=sys.stderr)
            print("  2. Specify path with: -c /path/to/chromedriver", file=sys.stderr)
            sys.exit(1)
        print(f"Using ChromeDriver: {chromedriver_path}")

    # Create output directory
    output_dir = Path(args.output)
    screenshots_dir = output_dir / 'screenshots'
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    # Load URLs
    try:
        with open(args.input, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"ERROR: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    if not urls:
        print("ERROR: No URLs found in input file", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(urls)} URLs")
    print(f"Output directory: {screenshots_dir}")

    # Process each URL
    success_count = 0
    fail_count = 0

    for i, url in enumerate(urls, 1):
        temp_dir = None
        try:
            print(f"[{i}/{len(urls)}] Processing: {url}")

            # Create driver
            driver, temp_dir = create_driver(chromedriver_path, args.width, args.height)

            # Navigate to URL
            driver.get(url)
            title = driver.title
            print(f"  ✓ Loaded: {title[:60]}")

            # Save screenshot
            filename = get_safe_filename(url)
            filepath = screenshots_dir / filename
            driver.save_screenshot(str(filepath))
            size = filepath.stat().st_size
            print(f"  ✓ Screenshot: {filename} ({size} bytes)")

            # Close driver
            driver.quit()
            success_count += 1

        except Exception as e:
            print(f"  ✗ Failed: {e}")
            fail_count += 1

        finally:
            # Cleanup temp directory
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    print(f"\n{'='*60}")
    print(f"Summary: {success_count} succeeded, {fail_count} failed")
    print(f"Screenshots saved to: {screenshots_dir}")

    sys.exit(0 if fail_count == 0 else 1)


if __name__ == '__main__':
    main()
