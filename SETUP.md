# Threat Intelligence Toolkit - Setup Guide

Cross-platform installation guide for Linux, macOS, and Windows.

## Quick Start

```bash
# Clone the repository
git clone <your-repo-url> Threat_Intel_Tools
cd Threat_Intel_Tools

# Run dependency check and auto-installer
python3 utils/dependency_manager.py
```

The dependency manager will automatically:
- ✓ Check Python version (3.8+ required)
- ✓ Install missing Python packages
- ✓ Detect and configure Chrome/Chromium
- ✓ Download version-matched ChromeDriver
- ✓ Install Go reconnaissance tools
- ✓ Verify system tools

## Platform-Specific Instructions

### Linux / WSL

**Prerequisites:**
```bash
# Update package lists
sudo apt-get update

# Install Python 3.8+ (if not already installed)
sudo apt-get install python3 python3-pip

# Install Go (for reconnaissance tools)
sudo apt-get install golang-go

# Install Chrome/Chromium (required for screenshots)
sudo apt-get install chromium-browser
```

**Run Setup:**
```bash
python3 utils/dependency_manager.py
```

### macOS

**Prerequisites:**
```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3
brew install python3

# Install Go
brew install go

# Install Chrome
brew install --cask google-chrome
```

**Run Setup:**
```bash
python3 utils/dependency_manager.py
```

### Windows

**Option 1: WSL (Recommended)**

Windows Subsystem for Linux provides the best compatibility:

1. Install WSL: `wsl --install`
2. Install Ubuntu from Microsoft Store
3. Follow Linux/WSL instructions above

**Option 2: Native Windows**

1. Install Python 3.8+ from https://python.org
2. Install Go from https://go.dev/dl/
3. Install Chrome from https://www.google.com/chrome/
4. Run in PowerShell:
```powershell
python utils/dependency_manager.py
```

## Manual Installation

If automatic installation fails, install dependencies manually:

### Python Packages

```bash
pip install requests selenium tqdm pandas pyyaml portalocker python-docx webdriver-manager
```

On Linux, you may need `--break-system-packages`:
```bash
pip install --break-system-packages requests selenium tqdm pandas pyyaml portalocker python-docx webdriver-manager
```

### Go Tools

```bash
# Ensure GOPATH is set
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Install tools
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/lc/gau/v2/cmd/gau@latest
```

### System Tools

**Linux/WSL:**
```bash
sudo apt-get install whatweb whois dnsutils
```

**macOS:**
```bash
brew install whatweb whois bind
```

**Windows:**
- System tools are optional on Windows
- Most functionality works without them

## ChromeDriver Setup

ChromeDriver is automatically downloaded to match your Chrome version.

**Manual Installation (if needed):**

1. Check Chrome version:
   - Linux: `chromium-browser --version`
   - macOS: `"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --version`
   - Windows: Open Chrome → Help → About

2. Download matching ChromeDriver from:
   https://chromedriver.chromium.org/downloads

3. Place in toolkit directory:
   ```bash
   # Example for version 142
   mv chromedriver chromedriver_142
   chmod +x chromedriver_142  # Linux/macOS only
   ```

## Verification

Test that everything is installed correctly:

```bash
# Quick dependency check
python3 check_dependencies.py

# Full dependency report
python3 utils/dependency_manager.py

# Test screenshot functionality
python3 simple_screenshot.py -i test_urls.txt -o test_output
```

## Configuration

### Environment Variables

```bash
# Execution mode (dev/quick/production)
export TI_MODE=dev

# Skip dependency check (for testing)
export SKIP_DEPENDENCY_CHECK=1

# Custom GOPATH (optional)
export GOPATH=/custom/path
```

### Config Files

Edit files in `config/` directory:

- `environment.yml` - Execution mode and target caps
- `recon.yml` - Reconnaissance module settings
- `httpx.yml` - HTTP probing stealth modes
- `screenshots.yml` - Screenshot service settings
- And more...

## Troubleshooting

### "Python 3.8+ required"

Install a newer Python version for your platform.

### "Chrome/Chromium not installed"

Screenshots will be disabled. Install Chrome:
- Linux: `sudo apt-get install chromium-browser`
- macOS: `brew install --cask google-chrome`
- Windows: Download from https://www.google.com/chrome/

### "ChromeDriver version mismatch"

Run `python3 utils/dependency_manager.py` to auto-download the correct version.

### "Go tools not found"

Ensure Go is installed and GOPATH/bin is in your PATH:
```bash
export PATH=$PATH:$HOME/go/bin
```

### Permission Denied (Linux/macOS)

Make scripts executable:
```bash
chmod +x *.py
chmod +x chromedriver_*
```

## Updating

Pull latest changes and re-run dependency check:

```bash
git pull
python3 utils/dependency_manager.py
```

## Support

For issues or questions:
- Check existing issues: [GitHub Issues](https://github.com/yourusername/Threat_Intel_Tools/issues)
- Review CLAUDE.md for detailed documentation
- Run diagnostic: `python3 utils/dependency_manager.py`
