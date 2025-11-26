#!/usr/bin/env python3
"""
Quick Dependency Check
Validates that all required dependencies are installed.
Auto-installs missing dependencies with user consent.
"""
import sys
from pathlib import Path

# Add utils to path
sys.path.insert(0, str(Path(__file__).parent))

from utils.dependency_manager import DependencyManager


def check_and_install_dependencies(auto_install: bool = False) -> bool:
    """
    Check dependencies and optionally auto-install.

    Args:
        auto_install: If True, automatically install missing dependencies without prompting

    Returns:
        True if all dependencies are satisfied, False otherwise
    """
    dm = DependencyManager()

    print("=" * 70)
    print("Checking dependencies...")
    print("=" * 70)

    all_satisfied = True

    # Check Python version
    if not dm.check_python_version():
        print("✗ Python 3.8+ required")
        return False

    # Check critical Python packages
    critical_packages = ['requests', 'selenium', 'pyyaml', 'pandas', 'portalocker']
    missing_packages = []

    for package in critical_packages:
        if not dm.check_python_package(package):
            missing_packages.append(package)

    if missing_packages:
        print(f"\n✗ Missing Python packages: {', '.join(missing_packages)}")

        if auto_install:
            print("Auto-installing...")
            installed, failed = dm.install_python_packages(missing_packages)
            if failed:
                print(f"✗ Failed to install: {', '.join(failed)}")
                all_satisfied = False
        else:
            response = input("Install missing packages now? [Y/n]: ").strip().lower()
            if response in ['', 'y', 'yes']:
                installed, failed = dm.install_python_packages(missing_packages)
                if failed:
                    print(f"✗ Failed to install: {', '.join(failed)}")
                    all_satisfied = False
            else:
                all_satisfied = False

    # Check Chrome and ChromeDriver
    chrome_path = dm.find_chrome()
    if not chrome_path:
        print("\n✗ Chrome/Chromium not installed (required for screenshots)")
        print("  Install instructions:")
        if dm.platform in ['linux', 'wsl']:
            print("    sudo apt-get install chromium-browser")
        elif dm.platform == 'macos':
            print("    brew install --cask google-chrome")
        elif dm.platform == 'windows':
            print("    Download from https://www.google.com/chrome/")

        # Screenshots are optional, so don't fail
        print("  ⚠ Screenshot functionality will be disabled")
    else:
        # Check for ChromeDriver
        version = dm.get_chrome_version(chrome_path)
        if version:
            major_version = version.split('.')[0]
            chromedriver_candidates = [
                dm.workspace_root / f'chromedriver_{major_version}',
                dm.workspace_root / f'chromedriver_{major_version}.exe',
                Path.home() / 'go' / 'bin' / 'chromedriver',
            ]

            chromedriver_found = any(p.exists() for p in chromedriver_candidates)

            if not chromedriver_found:
                print(f"\n✗ ChromeDriver {major_version} not found")

                if auto_install:
                    print("Auto-downloading ChromeDriver...")
                    chromedriver_path = dm.download_chromedriver(version, dm.cache_dir)
                    if not chromedriver_path:
                        print("  ⚠ Screenshot functionality will be disabled")
                else:
                    response = input(f"Download ChromeDriver {version}? [Y/n]: ").strip().lower()
                    if response in ['', 'y', 'yes']:
                        chromedriver_path = dm.download_chromedriver(version, dm.cache_dir)
                        if not chromedriver_path:
                            print("  ⚠ Screenshot functionality will be disabled")

    # Check Go tools (optional but recommended)
    go_tools = ['httpx', 'subfinder', 'assetfinder', 'gau']
    missing_go_tools = [tool for tool in go_tools if not dm.check_go_tool(tool)]

    if missing_go_tools:
        print(f"\n✗ Missing Go tools: {', '.join(missing_go_tools)}")

        if auto_install and dm.check_system_tool('go'):
            print("Auto-installing Go tools...")
            go_packages = {
                'httpx': 'github.com/projectdiscovery/httpx/cmd/httpx@latest',
                'subfinder': 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
                'assetfinder': 'github.com/tomnomnom/assetfinder@latest',
                'gau': 'github.com/lc/gau/v2/cmd/gau@latest'
            }
            for tool in missing_go_tools:
                if tool in go_packages:
                    dm.install_go_tool(go_packages[tool])
        elif not auto_install:
            print("  Run 'python3 utils/dependency_manager.py' to install")

        # Go tools are recommended but not critical
        print("  ⚠ Some reconnaissance modules may not work")

    # Check system tools (optional)
    system_tools = ['whatweb', 'whois']
    missing_system_tools = [tool for tool in system_tools if not dm.check_system_tool(tool)]

    if missing_system_tools:
        print(f"\n✗ Missing system tools: {', '.join(missing_system_tools)}")
        print("  Run 'python3 utils/dependency_manager.py' for installation instructions")
        print("  ⚠ Some vulnerability scanning modules may not work")

    print("\n" + "=" * 70)
    if all_satisfied:
        print("✓ All critical dependencies satisfied!")
    else:
        print("⚠ Some dependencies are missing")
        print("  Run: python3 utils/dependency_manager.py")
        print("  for full dependency installation")
    print("=" * 70)

    return all_satisfied


def main():
    """Run dependency check."""
    import argparse

    parser = argparse.ArgumentParser(description='Check and install dependencies')
    parser.add_argument('--auto-install', action='store_true',
                       help='Automatically install missing dependencies without prompting')
    parser.add_argument('--skip', action='store_true',
                       help='Skip dependency check (for testing)')

    args = parser.parse_args()

    if args.skip:
        print("Skipping dependency check...")
        return 0

    success = check_and_install_dependencies(auto_install=args.auto_install)

    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
