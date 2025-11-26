#!/usr/bin/env python3
"""
Cross-Platform Dependency Manager
Automatically checks and installs required dependencies for the Threat Intel Toolkit.
Supports: Linux, macOS, Windows (WSL and native)
"""
import os
import sys
import platform
import subprocess
import shutil
import tempfile
import zipfile
import requests
from pathlib import Path
from typing import Tuple, Optional, List


class DependencyManager:
    """Manages dependencies across different platforms."""

    def __init__(self, workspace_root: Optional[Path] = None):
        self.workspace_root = workspace_root or Path(__file__).parent.parent
        self.platform = self._detect_platform()
        self.arch = self._detect_architecture()
        self.cache_dir = self.workspace_root / 'cache'
        self.cache_dir.mkdir(exist_ok=True)

    def _detect_platform(self) -> str:
        """Detect the operating system."""
        system = platform.system().lower()
        if system == 'linux':
            # Check if running in WSL
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
        else:
            return 'unknown'

    def _detect_architecture(self) -> str:
        """Detect system architecture."""
        machine = platform.machine().lower()
        if machine in ['amd64', 'x86_64']:
            return 'x64'
        elif machine in ['arm64', 'aarch64']:
            return 'arm64'
        elif machine in ['i386', 'i686', 'x86']:
            return 'x32'
        else:
            return machine

    def check_python_version(self) -> bool:
        """Check if Python version is 3.8+."""
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 8):
            print(f"ERROR: Python 3.8+ required, found {version.major}.{version.minor}", file=sys.stderr)
            return False
        return True

    def check_python_package(self, package: str, import_name: Optional[str] = None) -> bool:
        """Check if a Python package is installed."""
        import_name = import_name or package
        try:
            __import__(import_name)
            return True
        except ImportError:
            return False

    def install_python_package(self, package: str, use_break_system_packages: bool = False) -> bool:
        """Install a Python package using pip."""
        try:
            cmd = [sys.executable, '-m', 'pip', 'install', package]
            if use_break_system_packages:
                cmd.append('--break-system-packages')

            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            print(f"Failed to install {package}: {e}", file=sys.stderr)
            return False

    def install_python_packages(self, packages: List[str]) -> Tuple[List[str], List[str]]:
        """Install multiple Python packages. Returns (installed, failed)."""
        installed = []
        failed = []

        # Try standard pip first
        for package in packages:
            if self.check_python_package(package):
                print(f"  ✓ {package} already installed")
                installed.append(package)
            else:
                print(f"  Installing {package}...", end=' ')
                if self.install_python_package(package):
                    print("✓")
                    installed.append(package)
                # Try with --break-system-packages on Linux
                elif self.platform in ['linux', 'wsl']:
                    if self.install_python_package(package, use_break_system_packages=True):
                        print("✓ (with --break-system-packages)")
                        installed.append(package)
                    else:
                        print("✗")
                        failed.append(package)
                else:
                    print("✗")
                    failed.append(package)

        return installed, failed

    def find_chrome(self) -> Optional[Path]:
        """Find Chrome/Chromium installation."""
        if self.platform in ['linux', 'wsl']:
            candidates = [
                '/usr/bin/google-chrome',
                '/usr/bin/chromium-browser',
                '/usr/bin/chromium',
                '/snap/bin/chromium',
                shutil.which('google-chrome'),
                shutil.which('chromium-browser'),
                shutil.which('chromium')
            ]
        elif self.platform == 'macos':
            candidates = [
                '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
                '/Applications/Chromium.app/Contents/MacOS/Chromium',
                shutil.which('google-chrome'),
                shutil.which('chromium')
            ]
        elif self.platform == 'windows':
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
                return Path(path)

        return None

    def get_chrome_version(self, chrome_path: Path) -> Optional[str]:
        """Get Chrome version."""
        try:
            if self.platform in ['linux', 'wsl', 'macos']:
                result = subprocess.run([str(chrome_path), '--version'],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Extract version number (e.g., "Google Chrome 142.0.7444.175")
                    version = result.stdout.strip().split()[-1]
                    return version
            elif self.platform == 'windows':
                # Windows version detection
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                    r'Software\Google\Chrome\BLBeacon')
                version, _ = winreg.QueryValueEx(key, 'version')
                return version
        except Exception as e:
            print(f"Failed to get Chrome version: {e}", file=sys.stderr)

        return None

    def download_chromedriver(self, version: str, dest_dir: Path) -> Optional[Path]:
        """Download ChromeDriver for the specified version."""
        # Major version (e.g., 142 from 142.0.7444.175)
        major_version = version.split('.')[0]

        # Determine platform string for download URL
        if self.platform in ['linux', 'wsl']:
            platform_str = 'linux64' if self.arch == 'x64' else 'linux32'
        elif self.platform == 'macos':
            if self.arch == 'arm64':
                platform_str = 'mac-arm64'
            else:
                platform_str = 'mac-x64'
        elif self.platform == 'windows':
            platform_str = 'win64' if self.arch == 'x64' else 'win32'
        else:
            print(f"Unsupported platform: {self.platform}", file=sys.stderr)
            return None

        # Try Chrome for Testing URL (newer versions)
        url = f'https://storage.googleapis.com/chrome-for-testing-public/{version}/{platform_str}/chromedriver-{platform_str}.zip'

        print(f"Downloading ChromeDriver {version} for {self.platform} ({self.arch})...")
        print(f"URL: {url}")

        try:
            response = requests.get(url, timeout=60)
            if response.status_code == 200:
                # Save to temp file
                with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp:
                    tmp.write(response.content)
                    zip_path = Path(tmp.name)

                # Extract
                extract_dir = dest_dir / f'chromedriver_{major_version}'
                extract_dir.mkdir(parents=True, exist_ok=True)

                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)

                # Find the chromedriver binary
                if self.platform == 'windows':
                    chromedriver_name = 'chromedriver.exe'
                else:
                    chromedriver_name = 'chromedriver'

                # Search for chromedriver in extracted files
                for root, dirs, files in os.walk(extract_dir):
                    if chromedriver_name in files:
                        chromedriver_path = Path(root) / chromedriver_name
                        # Make executable on Unix
                        if self.platform in ['linux', 'wsl', 'macos']:
                            chromedriver_path.chmod(0o755)

                        # Move to workspace root
                        final_path = self.workspace_root / f'chromedriver_{major_version}'
                        if self.platform == 'windows':
                            final_path = final_path.with_suffix('.exe')

                        shutil.copy2(chromedriver_path, final_path)

                        # Cleanup
                        os.unlink(zip_path)
                        shutil.rmtree(extract_dir, ignore_errors=True)

                        print(f"✓ ChromeDriver downloaded to: {final_path}")
                        return final_path

                print("✗ ChromeDriver binary not found in archive", file=sys.stderr)
                return None

            else:
                print(f"✗ Download failed: HTTP {response.status_code}", file=sys.stderr)
                return None

        except Exception as e:
            print(f"✗ Failed to download ChromeDriver: {e}", file=sys.stderr)
            return None

    def check_go_tool(self, tool_name: str) -> bool:
        """Check if a Go tool is installed."""
        return shutil.which(tool_name) is not None

    def install_go_tool(self, package_url: str) -> bool:
        """Install a Go tool using 'go install'."""
        try:
            # Check if Go is installed
            if not shutil.which('go'):
                print("✗ Go is not installed. Please install Go first.", file=sys.stderr)
                return False

            env = os.environ.copy()
            # Set GOPATH if not set
            if 'GOPATH' not in env:
                home = Path.home()
                env['GOPATH'] = str(home / 'go')

            # Add GOPATH/bin to PATH
            gopath_bin = Path(env['GOPATH']) / 'bin'
            env['PATH'] = f"{gopath_bin}:{env.get('PATH', '')}"

            result = subprocess.run(['go', 'install', '-v', package_url],
                                  env=env, capture_output=True, text=True, timeout=300)
            return result.returncode == 0

        except Exception as e:
            print(f"Failed to install {package_url}: {e}", file=sys.stderr)
            return False

    def check_system_tool(self, tool_name: str) -> bool:
        """Check if a system tool is installed."""
        return shutil.which(tool_name) is not None

    def install_system_tool_apt(self, package_name: str) -> bool:
        """Install a system tool using apt (Linux/WSL)."""
        try:
            # Update package list
            subprocess.run(['sudo', 'apt-get', 'update'],
                         capture_output=True, timeout=120, check=False)

            # Install package
            result = subprocess.run(['sudo', 'apt-get', 'install', '-y', package_name],
                                  capture_output=True, text=True, timeout=300)
            return result.returncode == 0

        except Exception as e:
            print(f"Failed to install {package_name}: {e}", file=sys.stderr)
            return False

    def install_system_tool_brew(self, package_name: str) -> bool:
        """Install a system tool using Homebrew (macOS)."""
        try:
            result = subprocess.run(['brew', 'install', package_name],
                                  capture_output=True, text=True, timeout=300)
            return result.returncode == 0

        except Exception as e:
            print(f"Failed to install {package_name}: {e}", file=sys.stderr)
            return False

    def setup_chrome_and_chromedriver(self) -> Tuple[Optional[Path], Optional[Path]]:
        """Setup Chrome and ChromeDriver. Returns (chrome_path, chromedriver_path)."""
        print("\n=== Chrome/ChromeDriver Setup ===")

        # Find Chrome
        chrome_path = self.find_chrome()
        if not chrome_path:
            print("✗ Chrome/Chromium not found")
            print("\nPlease install Chrome or Chromium:")
            if self.platform in ['linux', 'wsl']:
                print("  Linux/WSL: sudo apt-get install chromium-browser")
            elif self.platform == 'macos':
                print("  macOS: brew install --cask google-chrome")
            elif self.platform == 'windows':
                print("  Windows: Download from https://www.google.com/chrome/")
            return None, None

        print(f"✓ Chrome found: {chrome_path}")

        # Get Chrome version
        version = self.get_chrome_version(chrome_path)
        if not version:
            print("✗ Could not determine Chrome version")
            return chrome_path, None

        print(f"✓ Chrome version: {version}")

        # Check for matching ChromeDriver
        major_version = version.split('.')[0]
        chromedriver_candidates = [
            self.workspace_root / f'chromedriver_{major_version}',
            self.workspace_root / f'chromedriver_{major_version}.exe',
            Path.home() / 'go' / 'bin' / 'chromedriver',
            Path.home() / 'go' / 'bin' / 'chromedriver.exe',
        ]

        for candidate in chromedriver_candidates:
            if candidate.exists():
                print(f"✓ ChromeDriver found: {candidate}")
                return chrome_path, candidate

        # Download ChromeDriver
        print(f"Downloading ChromeDriver {version}...")
        chromedriver_path = self.download_chromedriver(version, self.cache_dir)

        if chromedriver_path:
            # Create symlink in go/bin if it exists
            gobin = Path.home() / 'go' / 'bin'
            if gobin.exists():
                symlink_name = 'chromedriver.exe' if self.platform == 'windows' else 'chromedriver'
                symlink_path = gobin / symlink_name
                try:
                    if symlink_path.exists():
                        symlink_path.unlink()
                    if self.platform == 'windows':
                        shutil.copy2(chromedriver_path, symlink_path)
                    else:
                        symlink_path.symlink_to(chromedriver_path)
                    print(f"✓ Created link: {symlink_path}")
                except Exception as e:
                    print(f"Warning: Could not create symlink: {e}")

            return chrome_path, chromedriver_path

        return chrome_path, None


def main():
    """Run dependency checks and installations."""
    print("=" * 70)
    print("Threat Intelligence Toolkit - Dependency Manager")
    print("=" * 70)

    dm = DependencyManager()

    print(f"\nPlatform: {dm.platform}")
    print(f"Architecture: {dm.arch}")
    print(f"Workspace: {dm.workspace_root}")

    # Check Python version
    print("\n=== Python Version ===")
    if dm.check_python_version():
        print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    else:
        sys.exit(1)

    # Check Python packages
    print("\n=== Python Packages ===")
    required_packages = [
        'requests', 'selenium', 'tqdm', 'pandas', 'pyyaml',
        'portalocker', 'python-docx', 'webdriver-manager'
    ]

    installed, failed = dm.install_python_packages(required_packages)

    if failed:
        print(f"\n✗ Failed to install: {', '.join(failed)}")
        print("Please install manually:")
        for pkg in failed:
            print(f"  pip install {pkg}")

    # Setup Chrome and ChromeDriver
    chrome_path, chromedriver_path = dm.setup_chrome_and_chromedriver()

    if not chrome_path:
        print("\n⚠ Warning: Chrome not installed. Screenshot functionality will not work.")

    if not chromedriver_path:
        print("\n⚠ Warning: ChromeDriver not available. Screenshot functionality will not work.")

    # Check Go tools
    print("\n=== Go Tools ===")
    go_tools = {
        'httpx': 'github.com/projectdiscovery/httpx/cmd/httpx@latest',
        'subfinder': 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
        'assetfinder': 'github.com/tomnomnom/assetfinder@latest',
        'gau': 'github.com/lc/gau/v2/cmd/gau@latest'
    }

    for tool, package in go_tools.items():
        if dm.check_go_tool(tool):
            print(f"  ✓ {tool}")
        else:
            print(f"  ✗ {tool} not found")
            if shutil.which('go'):
                print(f"    Installing {tool}...", end=' ')
                if dm.install_go_tool(package):
                    print("✓")
                else:
                    print("✗")
            else:
                print(f"    Please install Go, then run: go install {package}")

    # Check system tools
    print("\n=== System Tools ===")
    system_tools = ['whatweb', 'whois', 'dig']

    for tool in system_tools:
        if dm.check_system_tool(tool):
            print(f"  ✓ {tool}")
        else:
            print(f"  ✗ {tool} not found")
            if dm.platform in ['linux', 'wsl']:
                print(f"    Install with: sudo apt-get install {tool}")
            elif dm.platform == 'macos':
                print(f"    Install with: brew install {tool}")

    print("\n" + "=" * 70)
    print("Dependency check complete!")
    print("=" * 70)


if __name__ == '__main__':
    main()
