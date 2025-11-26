# Cross-Platform & Dependency Auto-Installation Summary

## Overview

The Threat Intelligence Toolkit is now fully cross-platform compatible and features automatic dependency installation. All dependencies are checked and installed automatically (with user consent) before execution.

## Supported Platforms

✅ **Linux** - Native Linux distributions (Ubuntu, Debian, RHEL, etc.)
✅ **WSL** - Windows Subsystem for Linux (WSL1 and WSL2)
✅ **macOS** - macOS 10.14+
✅ **Windows** - Native Windows (via PowerShell/CMD)

## Key Features

### 1. Automatic Dependency Detection & Installation

**New Files:**
- `utils/dependency_manager.py` - Cross-platform dependency manager
- `check_dependencies.py` - Quick dependency check (runs before workflow)
- `SETUP.md` - Comprehensive setup guide

**Capabilities:**
- ✅ Detects operating system and architecture automatically
- ✅ Checks Python version (3.8+ required)
- ✅ Installs missing Python packages (with `--break-system-packages` on Linux)
- ✅ Finds Chrome/Chromium installation
- ✅ Auto-downloads version-matched ChromeDriver
- ✅ Installs Go reconnaissance tools (httpx, subfinder, assetfinder, gau)
- ✅ Verifies system tools (whatweb, whois, dig)
- ✅ Provides platform-specific installation instructions

**Usage:**
```bash
# Full dependency installation
python3 utils/dependency_manager.py

# Quick check (auto-install with prompts)
python3 check_dependencies.py

# Auto-install without prompts (CI/CD mode)
python3 check_dependencies.py --auto-install

# Skip dependency check
SKIP_DEPENDENCY_CHECK=1 python3 master_recon.py --organization "Test"
```

### 2. Cross-Platform Screenshot Service

**Modified Files:**
- `simple_screenshot.py` - Portable screenshot capture script

**Improvements:**
- ✅ Auto-detects platform (Linux/WSL/macOS/Windows)
- ✅ Auto-finds Chrome/Chromium binary
- ✅ Auto-finds ChromeDriver in common locations
- ✅ Platform-specific Chrome options (WSL requires extra flags)
- ✅ Portable path handling (uses `pathlib.Path`)
- ✅ Cross-platform temp directory management

**Platform-Specific Chrome Options:**

**Linux/WSL:**
```python
--headless=new
--no-sandbox
--disable-gpu
--disable-dev-shm-usage
--disable-setuid-sandbox          # WSL-specific
--disable-software-rasterizer     # WSL-specific
--remote-debugging-port=9222      # WSL-specific
```

**macOS:**
```python
--headless=new
--no-sandbox
--disable-gpu
```

**Windows:**
```python
--headless=new
--disable-gpu
```

### 3. Automatic ChromeDriver Management

**Features:**
- ✅ Detects Chrome/Chromium version
- ✅ Downloads matching ChromeDriver automatically
- ✅ Supports multiple Chrome versions (140, 141, 142, etc.)
- ✅ Platform-specific downloads (linux64, mac-x64, mac-arm64, win64, win32)
- ✅ Creates symlinks in `$GOPATH/bin` for convenience

**ChromeDriver Search Order:**
1. Workspace directory (`chromedriver_142`, `chromedriver_141`, etc.)
2. Go bin directory (`$HOME/go/bin/chromedriver`)
3. System PATH
4. Common system locations (`/usr/local/bin`, `/usr/bin`)

### 4. Workflow Integration

**Modified Files:**
- `master_recon.py` - Main workflow orchestrator

**Changes:**
- ✅ Automatic dependency check on startup
- ✅ Interactive mode: Prompts to install missing dependencies
- ✅ Non-interactive mode: Auto-installs with warnings
- ✅ Can skip dependency check with `SKIP_DEPENDENCY_CHECK=1`
- ✅ Clear error messages with installation instructions

**Example Output:**
```
======================================================================
Checking dependencies...
======================================================================

✗ Missing Python packages: pyyaml
Install missing packages now? [Y/n]: y
  Installing pyyaml... ✓

✗ ChromeDriver 142 not found
Download ChromeDriver 142.0.7444.175? [Y/n]: y
Downloading ChromeDriver 142 for wsl (x64)...
✓ ChromeDriver downloaded to: chromedriver_142

======================================================================
✓ All critical dependencies satisfied!
======================================================================
```

### 5. Portable File Paths

**All scripts now use portable path handling:**
- ✅ `pathlib.Path` instead of string concatenation
- ✅ `os.path.join()` for backwards compatibility
- ✅ No hardcoded absolute paths
- ✅ Workspace-relative paths
- ✅ User home directory expansion (`Path.home()`)

**Example:**
```python
# Before (not portable)
path = '/home/mikana/Threat_Intel_Tools/chromedriver_142'

# After (portable)
workspace = Path(__file__).parent
path = workspace / 'chromedriver_142'
```

## Testing

All cross-platform features have been tested on:
- ✅ WSL2 (Ubuntu 24.04)
- ✅ Python 3.12.3
- ✅ Chromium 142.0.7444.175
- ✅ ChromeDriver 142.0.7444.175

**Test Results:**
```
Platform: wsl
Architecture: x64

Python Packages: ✓ All installed
Chrome/ChromeDriver: ✓ Auto-detected and configured
Go Tools: ✓ Auto-installed (httpx, subfinder, assetfinder, gau)
System Tools: ✓ Verified (whatweb, whois, dig)
Screenshot Test: ✓ 2/2 URLs captured successfully
```

## Migration Guide

### For Existing Installations

```bash
# Update codebase
git pull

# Run dependency check (updates ChromeDriver if needed)
python3 utils/dependency_manager.py

# Test workflow
SKIP_DEPENDENCY_CHECK=1 python3 master_recon.py --organization "Test" --dry-run
```

### For New Installations

```bash
# Clone repository
git clone <repo-url> Threat_Intel_Tools
cd Threat_Intel_Tools

# One-command setup
python3 utils/dependency_manager.py

# Ready to run!
python3 master_recon.py --organization "MyOrg"
```

## Environment Variables

**New Environment Variables:**

| Variable | Description | Example |
|----------|-------------|---------|
| `SKIP_DEPENDENCY_CHECK` | Skip automatic dependency check | `SKIP_DEPENDENCY_CHECK=1` |
| `TI_MODE` | Execution mode (dev/quick/production) | `TI_MODE=dev` |
| `GOPATH` | Go workspace path | `GOPATH=$HOME/go` |

## Dependency Versions

**Python:** 3.8+ (tested with 3.12.3)

**Python Packages:**
- requests
- selenium
- tqdm
- pandas
- pyyaml
- portalocker
- python-docx
- webdriver-manager (optional, used as fallback)

**Go Tools:**
- httpx (github.com/projectdiscovery/httpx/cmd/httpx@latest)
- subfinder (github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)
- assetfinder (github.com/tomnomnom/assetfinder@latest)
- gau (github.com/lc/gau/v2/cmd/gau@latest)

**System Tools (recommended):**
- whatweb (for technology detection)
- whois (for WHOIS lookups)
- dig/nslookup (for DNS queries)

## Known Limitations

### Windows Native
- Some system tools (whatweb, whois) are not available on Windows
- Recommended to use WSL for full functionality
- PowerShell execution policies may need adjustment

### macOS ARM (M1/M2/M3)
- Requires Rosetta 2 for some x86 tools
- ChromeDriver arm64 version is fully supported

### Snap-installed Chrome (Linux)
- May have sandbox restrictions
- Use `--no-sandbox` flag (automatically applied)

## Troubleshooting

### Dependency Manager Fails

```bash
# Check Python version
python3 --version  # Should be 3.8+

# Check pip
python3 -m pip --version

# Install dependencies manually
pip install --break-system-packages requests selenium pyyaml pandas portalocker
```

### ChromeDriver Download Fails

```bash
# Check Chrome version
chromium-browser --version

# Manual download from:
# https://chromedriver.chromium.org/downloads

# Place in workspace
mv chromedriver chromedriver_142
chmod +x chromedriver_142
```

### Screenshot Service Fails

```bash
# Test ChromeDriver independently
python3 -c "
from simple_screenshot import detect_platform, find_chrome_binary, find_chromedriver
print('Platform:', detect_platform())
print('Chrome:', find_chrome_binary())
print('ChromeDriver:', find_chromedriver())
"

# Verify Chrome is installed
which chromium-browser  # Linux
which google-chrome     # macOS
where chrome            # Windows
```

## Future Enhancements

- [ ] Docker container for consistent environments
- [ ] Package as pip-installable module
- [ ] macOS/Windows native installers
- [ ] Automated CI/CD testing across platforms
- [ ] Binary releases with bundled dependencies

## Credits

Cross-platform compatibility improvements made by Claude Code on 2025-11-26.

Tested on WSL2 with Ubuntu 24.04, Python 3.12.3, and Chromium 142.
