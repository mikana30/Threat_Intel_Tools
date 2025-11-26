# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a modular threat intelligence and reconnaissance workflow system that orchestrates 48+ security scanning stages through a JSON-driven pipeline. The system performs domain enumeration, vulnerability assessment, cloud misconfiguration detection, and threat intelligence enrichment against target organizations.

**Cross-Platform Compatible**: Runs on Linux, macOS, Windows (WSL and native), with automatic dependency installation.

## Setup and Dependencies

### Quick Start

The toolkit features automatic dependency detection and installation:

```bash
# First-time setup - installs all dependencies automatically
python3 utils/dependency_manager.py

# Or run the workflow - dependencies are checked automatically
python3 master_recon.py --organization "OrganizationName"
```

### Dependency Management

**Automatic Dependency Checking:**
- Master workflow (`master_recon.py`) checks dependencies before execution
- Interactive mode: Prompts to install missing packages
- Non-interactive mode: Auto-installs with warnings
- Can skip check: `SKIP_DEPENDENCY_CHECK=1 python3 master_recon.py ...`

**Key Files:**
- `utils/dependency_manager.py` - Full-featured cross-platform dependency manager
- `check_dependencies.py` - Quick dependency check (runs before workflow)
- `SETUP.md` - Comprehensive platform-specific setup guide
- `CROSS_PLATFORM.md` - Technical documentation of cross-platform features

**What's Automatically Installed:**
- ✅ Python packages (requests, selenium, pandas, pyyaml, etc.)
- ✅ Version-matched ChromeDriver for screenshots
- ✅ Go reconnaissance tools (httpx, subfinder, assetfinder, gau)
- ✅ System tool verification (whatweb, whois, dig)

**Supported Platforms:**
- Linux (Ubuntu, Debian, RHEL, etc.)
- WSL (Windows Subsystem for Linux 1 and 2)
- macOS (10.14+)
- Windows (native via PowerShell/CMD)

**Manual Installation:**
See `SETUP.md` for detailed platform-specific instructions.

### Environment Variables

```bash
# Skip dependency check (for testing/CI)
SKIP_DEPENDENCY_CHECK=1 python3 master_recon.py --organization "Test"

# Set execution mode
TI_MODE=dev python3 master_recon.py --organization "Test"

# Disable auto-update
TI_AUTO_UPDATE=disabled python3 master_recon.py --organization "Test"
```

## Running the Workflow

### Full Workflow Execution
```bash
# Production mode (no limits)
python3 master_recon.py --organization "OrganizationName"

# Resume from specific stage
python3 master_recon.py --organization "OrganizationName" \
  --start-stage 5 \
  --output-dir "results/OrganizationName_20251121_083010"

# Set execution mode via environment
TI_MODE=production python3 master_recon.py --organization "OrganizationName"

# Disable auto-update check
TI_AUTO_UPDATE=disabled python3 master_recon.py --organization "OrganizationName"
```

### Execution Modes
Configure in `config/environment.yml`:
- **dev**: 10 target cap (fast validation, ~5-10 min)
- **quick**: 1000 target cap (performance testing, ~15-30 min)
- **production**: No limits (full scan, hours)

### Target Configuration
Edit `targets.txt` with one domain per line:
```
example.com
ornl.gov
fnal.gov
```

## Workflow Architecture

The workflow is defined in `workflow_spec.json` with 48 sequential stages organized into 4 phases.

**Execution Model:**
- Stages execute sequentially (stage N+1 waits for stage N to complete)
- Scripts within a stage run in parallel (using ThreadPoolExecutor)
- Placeholder interpolation: `{output_dir}` and `{organization}` are replaced at runtime

**Key Phases:**

### Phase 1: Target Discovery & Enumeration (Stages 1-10)
- **Target Normalization**: Automatically extracts apex domains (e.g., `www6.slac.edu` → `slac.stanford.edu`)
- **Recon Orchestration**: Parallel subdomain enumeration using subdomz, assetfinder, subfinder, gau
- **DNS Resolution**: Resolves discovered domains to IP addresses
- **HTTP Probing**: Fast web service enumeration using httpx with basic tech detection
- **IP Harvesting**: Collects unique IPs for WHOIS lookups
- **Distributed WHOIS**: Batched WHOIS queries with state persistence

### Phase 2: Intelligence Gathering (Stages 11-25)
- **Domain Filtering**: Reduces noise using heuristics
- **DNS Suite**: Deep DNS analysis (MX, SPF, DMARC, DNSSEC)
- **Typosquat Monitoring**: Detects domain squatting
- **Certificate Transparency**: SSL/TLS cert analysis
- **Email Security Audit**: SPF/DMARC/MX validation
- **Cloud Storage Scanning**: S3, Azure, GCP bucket enumeration

### Phase 3: Vulnerability Assessment (Stages 26-44)
- **Web Asset Discovery**: Identifies live web hosts
- **Tech Stack Detection**: Fingerprints technologies (WordPress, Drupal, frameworks)
- **Admin Panel Detection**: Enumerates 17 common admin paths per domain
- **Git Exposure**: Scans for exposed .git repositories
- **SSL/TLS Analysis**: Certificate validation and expiry
- **WAF Detection**: Identifies web application firewalls
- **VNC Scanning**: Detects VNC services (batched with state persistence)
- **Port Discovery**: Open port enumeration
- **Subdomain Takeover**: Checks for takeover vulnerabilities
- **Screenshot Capture**: Visual documentation of priority targets

### Phase 4: Enrichment & Reporting (Stages 45-48)
- **Threat Context Enrichment**: CVE correlation via NVD/CIRCL APIs (with SQLite caching)
- **Data Normalization**: Merges and deduplicates outputs
- **WHOIS Integration**: Enriches results with ownership data
- **Change Detection**: Compares against baseline, archives previous baselines
- **Report Generation**: Creates Word doc + interactive HTML appendix

## Key Components

### Orchestration
- **master_recon.py**: Main workflow executor
  - Loads workflow_spec.json
  - Manages stage execution with ThreadPoolExecutor (scripts within stages run in parallel)
  - Handles script resolution (case-insensitive, path lookup)
  - Supports `--start-stage` for resumption
  - Preflight checks verify all scripts exist before execution

**Script Resolution Strategy:**
1. Exact file match in workspace directory
2. Case/space-insensitive match in workspace (handles "Dir Listing Checker.py" vs "Dir_Listing_Checker.py")
3. PATH lookup for external tools (subdomz, assetfinder, etc.)
4. Python scripts (.py) run via `python3`, others run directly after chmod +x

### Target Normalization
- **TargetNormalizer.py**: Intelligent apex domain extraction
  - Handles .edu, .ac.uk, multi-level TLDs
  - Preserves IPs and localhost
  - Use `--no-extract` flag to disable auto-extraction

### Modular Recon System
- **ReconOrchestrator.py**: Parallel subdomain enumeration
  - Configurable modules in `config/recon.yml`
  - Per-domain output directories
  - Aggregated results with source tracking
- **recon/modules/**: Individual recon module implementations
  - Base class: `recon/modules/base.py`
  - Available modules: subdomz, assetfinder, subfinder, gau, amass
  - Each module wraps external tool and implements standardized interface
  - Modules can be enabled/disabled per-domain in recon.yml

### State-Persistent Services
- **distributed_whois.py**: Batched WHOIS with JSON state file
- **vnc_scan.py**: VNC scanning with resumption support
- Both use `--state-file` to track progress across runs

### HTTP Probing System
- **httpx_probe.py**: Fast, comprehensive HTTP enumeration
  - Uses ProjectDiscovery's httpx tool for speed and stealth
  - Basic technology detection (frameworks, CMS, libraries)
  - Server header extraction and CDN identification
  - Page title extraction and TLS version detection
  - Configurable stealth modes in `config/httpx.yml`:
    - **Stealth mode**: 2 req/sec, high jitter, UA rotation (2-4 hours for 1000 hosts)
    - **Balanced mode**: 15 req/sec, moderate stealth (30-60 min for 1000 hosts)
    - **Fast mode**: 100 req/sec, minimal delays (5-15 min for 1000 hosts)
  - Auto-installation support via go install
  - Outputs enriched CSV with status codes, tech stack, response times
  - Complements tech_detection_service.py (httpx = broad/fast, tech_detection = deep/slow)

### Screenshot System
- **prepare_priority_screenshots.py**: Generates smart filtered target list
  - Filters admin login results (Status 200 only)
  - Includes default pages, directory listings, non-prod domains
  - CSV field size limit: 10MB (handles large Dir_Listing outputs)
- **smart_filter_screenshots.py**: Advanced noise reduction
  - Keeps 1-2 hits per domain (likely real)
  - Top 2 for 3-9 hits (mixed signal/noise)
  - Top 1 for 10+ hits (catch-all domains)
  - Prioritizes staging/qa/test environments
  - Typical reduction: 2,772 → 315 URLs (88.6%)
- **simple_screenshot.py**: Cross-platform screenshot capture (PRIMARY)
  - **Auto-detects platform**: Linux, WSL, macOS, Windows
  - **Auto-finds Chrome**: Searches common installation paths
  - **Auto-finds ChromeDriver**: Workspace, Go bin, system PATH
  - **Platform-specific options**: WSL sandbox flags, macOS paths, Windows configs
  - **Portable**: No hardcoded paths, works anywhere
  - **Fast**: Simple, reliable, single-threaded approach
  - Used by workflow (Stage 42)
- **screenshot_service.py**: Legacy multi-threaded screenshot service
  - Complex driver pooling with threading
  - Configurable threads/timeouts in `config/screenshots.yml`
  - May have issues with webdriver-manager auto-download
  - Recommended: Use `simple_screenshot.py` instead

### Threat Intelligence
- **threat_context_enricher.py**: CVE correlation
  - Queries NVD and CIRCL APIs
  - SQLite cache: `cache/cve_cache.db`
  - Outputs: threat_context.json, summary CSV, high-risk assets, remediation guidance
  - **Important**: Uses `datetime.timezone.utc` (not `datetime.UTC`) for Python 3.11+ compatibility

### Reporting
- **Reporting_Toolkit/generate_report.py**: Report generation
  - Client-agnostic (no hardcoded org names/IPs)
  - Filters typosquatting data (dns_a != empty)
  - EOL detection: Python 2.x, OpenSSL 1.0.x, PHP 5.x
  - WHOIS filtering for relevance
  - Outputs:
    - Threat_Intelligence_Report.docx (Word document with executive summary, findings, recommendations)
    - Interactive_Appendix.html (searchable/filterable data tables with appendix.js for interactivity)
  - Uses python-docx for Word generation
  - HTML appendix uses vanilla JS (no framework dependencies)

## Configuration Files

All configurations are in `config/`:

- **environment.yml**: Execution mode (dev/quick/production) and target caps
- **recon.yml**: Recon module toggles, workers, delays
- **httpx.yml**: HTTP probing stealth modes, rate limits, tech detection toggles
- **screenshots.yml**: Browser settings, threads, timeouts
- **tech_detection.yml**: Technology detection patterns
- **threat_intel.yml**: CVE API settings, cache config
- **whois.yml**: WHOIS batch sizing, rate limits
- **vnc.yml**: VNC scan settings
- **change_detection.yml**: Baseline comparison settings
- **cloud_storage.yml**: Multi-cloud bucket enumeration
- **s3.yml**: AWS S3-specific settings
- **domain_filters.yml**: Domain filtering heuristics
- **typosquat.yml**: Typosquatting detection patterns
- **dns.yml**: DNS analysis settings

## Output Structure

```
results/[ORGANIZATION]_[TIMESTAMP]/
├── raw_outputs/
│   ├── phase1/
│   │   ├── targets.json
│   │   ├── resolved.json
│   │   └── http_probe.csv
│   ├── recon_outputs/
│   │   └── [domain]/
│   │       ├── aggregated_domains.json
│   │       └── sources/
│   ├── whois_scan_state.json
│   ├── vnc_scan_state.json
│   ├── priority_screenshot_targets.txt
│   ├── priority_screenshot_targets_smart.txt
│   └── [module]_out.csv
├── threat_context/
│   ├── threat_context.json
│   ├── threat_context_summary.csv
│   └── high_risk_assets.txt
├── screenshots/
│   └── priority_targets/
├── changes/
│   ├── changes_summary.json
│   └── changes_detailed.csv
└── FINAL_REPORT/
    ├── Threat_Intelligence_Report.docx
    └── Interactive_Appendix.html
```

## Common Fixes

### CSV Field Size Errors
If you see `_csv.Error: field larger than field limit (131072)`:
```python
import csv
csv.field_size_limit(10 * 1024 * 1024)  # 10MB limit
```

### DateTime Compatibility
Always use `datetime.timezone.utc` instead of `datetime.UTC`:
```python
from datetime import datetime, timezone
timestamp = datetime.now(timezone.utc)
```

### ChromeDriver Version Mismatch
Screenshot failures due to driver/browser mismatch:
- Local version-matched driver: `chromedriver_141`
- screenshot_service.py has fallback strategy: webdriver-manager → local → system

### Admin Login False Positives
Domains returning 200 for 10+ admin paths are likely catch-all responses. Use `smart_filter_screenshots.py` to reduce noise.

### Cloud Scanner (Other_Buckets.py) Critical Notes

**IMPORTANT:** `Other_Buckets.py` was added in commit `694381a` (Nov 22, 2025) and the original version works correctly. Do NOT modify this file's threading logic, timeout handling, or session management without extensive testing.

**Known Issues:**
- The script uses 100 threads by default (`max_threads: 100` in `config/cloud_storage.yml`)
- Scans 6 cloud providers (AWS, Azure, GCP, DigitalOcean, Wasabi, + regional variants)
- Can take 15-30 minutes in production mode for 40+ domains
- Uses high CPU (300-700%) which is NORMAL and indicates healthy progress

**Troubleshooting Hung Scans:**
If the cloud scanner appears stuck, check if it's actually deadlocked:
```bash
# Check I/O activity (should change over 30 seconds)
cat /proc/[PID]/io | grep "rchar\|wchar" && sleep 30 && cat /proc/[PID]/io | grep "rchar\|wchar"

# Check thread states (futex_wait_queue for ALL threads = deadlock)
ps -eLo pid,tid,stat,wchan:30 | grep "^[[:space:]]*[PID]"

# Check CPU usage (should be 300-700%)
ps -p [PID] -o pid,%cpu,etime
```

**If you suspect a bug:** Check git history first. The original version from commit `694381a` is known working. Any "fixes" that add signal.alarm(), create fresh sessions per request, or modify the ThreadPoolExecutor structure will likely break it.

**Diagnostic command for deadlock investigation:**
```bash
# Generate full diagnostic report
echo "=== I/O Stats ===" && cat /proc/[PID]/io
echo "=== Thread States ===" && ps -eLo pid,tid,stat,wchan:30 | grep "^[[:space:]]*[PID]" | head -30
echo "=== Network Connections ===" && lsof -p [PID] -a -i 2>/dev/null | wc -l
echo "=== Process Info ===" && ps -p [PID] -o pid,ppid,cmd,%cpu,%mem,etime
```

### httpx Stealth Configuration

The workflow uses httpx for HTTP probing with configurable stealth modes in `config/httpx.yml`:

**Choosing the right mode:**
- **Stealth mode** (`mode: stealth`): Use for high-security targets, IDS/IPS avoidance
  - 2 requests/sec with 300ms jitter
  - User-Agent rotation across 20 browsers
  - Minimal feature detection
  - Runtime: 2-4 hours for 1000 hosts

- **Balanced mode** (`mode: balanced`): Default, recommended for most scans
  - 15 requests/sec with 50ms jitter
  - Moderate UA rotation (10 browsers)
  - Full tech detection enabled
  - Runtime: 30-60 minutes for 1000 hosts

- **Fast mode** (`mode: fast`): Time-constrained scans, low-security targets
  - 100 requests/sec with minimal jitter
  - No UA rotation
  - Basic detection only
  - Runtime: 5-15 minutes for 1000 hosts

**Key stealth features:**
- Randomized request timing (jitter) defeats pattern detection
- User-Agent rotation prevents fingerprinting
- Connection pooling mimics browser behavior
- Configurable rate limiting avoids triggering alerts
- HTTP/2 support for modern, legitimate-looking traffic

**Advanced customization:**
Edit `config/httpx.yml` to adjust:
- `rate_limit`: Max requests per second
- `threads`: Concurrent connections
- `jitter`: Random delay variance (ms)
- `user_agents`: Custom browser pool
- `custom_headers`: Additional headers for blending in

## Development Workflow

### Adding a New Scan Module

1. Create script in root directory (e.g., `New_Scanner.py`)
2. Add to `workflow_spec.json`:
```json
{
  "id": 49,
  "name": "Phase_New_Scanner",
  "scripts": [{
    "name": "New_Scanner.py",
    "flags": [
      "-i", "{output_dir}/raw_outputs/input.csv",
      "-o", "{output_dir}/raw_outputs/New_Scanner_out.csv"
    ]
  }]
}
```
3. Use `{output_dir}` placeholder for path interpolation
4. Output to `raw_outputs/` for report integration

### Resuming Failed Scans

If a scan stops mid-execution:
```bash
# Find the last completed stage in logs
grep "Finished Stage" ornl_run.log | tail -1

# Resume from next stage
python3 master_recon.py --organization "ORNL" \
  --output-dir "results/ORNL_20251121_083010" \
  --start-stage 5
```

State-persistent modules (WHOIS, VNC) automatically resume via `--state-file`.

## Testing

### Preflight Validation
The orchestrator runs preflight checks before execution:
- Verifies all scripts in workflow_spec.json exist
- Uses case-insensitive workspace lookup
- Checks PATH for external tools

### Dev Mode Testing
```bash
# Edit config/environment.yml
mode: dev  # Caps at 10 targets

# Run workflow
python3 master_recon.py --organization "TestOrg"
```

## Auto-Update System

The workflow includes built-in auto-update functionality:
- Checks for git repository updates before each run
- Prompts user to update if remote changes are available
- Safely handles local uncommitted changes (stash/restore)
- Can be disabled with `TI_AUTO_UPDATE=disabled` environment variable

**Auto-update workflow:**
1. Fetches latest changes from remote
2. Shows commit messages for available updates
3. Prompts user to update, with options to stash/restore local changes
4. Performs git pull if user confirms

## Important Notes

- **All Python scripts use Python 3.13+** (check shebang: `#!/usr/bin/env python3`)
- **Workflow stages are sequential** (no parallel stage execution)
- **Module execution within stages is parallel** (ThreadPoolExecutor with configurable workers)
- **State files enable resumption** for long-running scans (WHOIS, VNC)
- **Baselines are archived** before updates (see `baselines/archive/`)
- **Reports are client-agnostic** - no hardcoded organization names or IPs
- **Git repository is recommended** for multi-machine sync and auto-updates
- **Results, logs, and cache directories are git-ignored** to prevent committing sensitive data

## External Dependencies

Required tools (must be in PATH or workspace):
- httpx (Go binary from ProjectDiscovery - auto-installs if missing)
- subdomz (Go binary)
- assetfinder
- subfinder
- gau
- chromedriver (for screenshots)

Python packages managed via pip (see imports in individual scripts).

**httpx installation:**
```bash
# Automatic (via httpx_probe.py --auto-install flag)
# Already configured in workflow_spec.json Stage 5

# Manual installation
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Verify installation
httpx -version
```

## Multi-Machine Setup

To synchronize the toolkit across multiple machines:

1. **Initialize git repository** (if not already done):
```bash
git init
git remote add origin git@github.com:yourusername/Threat_Intel_Tools.git
git add .
git commit -m "Initial commit"
git push -u origin main
```

2. **Clone on additional machines**:
```bash
cd ~/Desktop/threat_intel
git clone git@github.com:yourusername/Threat_Intel_Tools.git "Threat Intel Tools and Work Flow"
```

3. **Auto-update will handle synchronization** on each run, or manually:
```bash
git pull  # Get latest changes
git add -u && git commit -m "description" && git push  # Share changes
```

See `SETUP_SYNC.md` for detailed multi-machine synchronization guide.

## Security Improvements Made

### Atomic File Operations
- Replaced direct file writes with atomic operations using `os.replace()`
- Prevents partial writes and race conditions in state files (WHOIS, VNC scan state)
- Ensures consistency across concurrent access

### File Locking & Synchronization
- Implemented `filelock` library for cross-platform file locking
- Prevents simultaneous modifications to shared state (baselines, cache)
- Graceful fallback for systems without native locking support

### Input Validation
- Path traversal protection: All user inputs validated against expected directories
- Command injection prevention: All subprocess calls use argument lists (no shell=True)
- Format validation: Domains, IPs, and file paths validated before use

### Subprocess Security
- Removed all `shell=True` invocations
- All commands pass as argument lists to subprocess
- Prevents shell injection vulnerabilities
- Example: `subprocess.run(['grep', '-r', pattern, directory])` instead of `subprocess.run(f'grep -r {pattern} {directory}', shell=True)`

### Secure Credential Handling
- API keys loaded from environment variables only (never hardcoded)
- `.env` file support for local development
- Config files (threat_intel.yml) excluded from git via .gitignore
- Sensitive data filtered from log output

## Environment Variable Configuration

### Required Variables
Set these before running the toolkit:

```bash
# Export or create .env file with:
export TI_MODE=production              # dev, quick, or production
export TI_AUTO_UPDATE=enabled          # enabled or disabled
export NVD_API_KEY=your_api_key        # For threat context enrichment
export CIRCL_CERT_API_KEY=your_key     # For certificate intelligence
```

### .env File Setup
```bash
# Create .env from example
cp .env.example .env

# Edit with your credentials
nano .env

# Load before running
source .env
python3 master_recon.py --organization "YourOrg"
```

### Configuration Files
- `config/environment.yml` - Execution mode and target caps
- `config/threat_intel.yml` - CVE API settings (git-ignored)
- `config/recon.yml` - Subdomain enumeration settings
- `config/httpx.yml` - HTTP probing stealth modes
- All other config files in `config/` directory

## Cross-Platform Compatibility

### Platform Support
- **Linux (primary)** - Full support, tested on Ubuntu 20.04+
- **macOS** - Supported, tested on Monterey+
- **Windows (WSL2)** - Fully supported, same as Linux
- **Windows (native)** - Limited support (recommend WSL2)

### Platform-Specific Notes

#### Linux/macOS/WSL2
```bash
# Standard setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 master_recon.py --organization "TestOrg"
```

#### Windows Native (limited support)
```powershell
# Use PowerShell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python master_recon.py --organization "TestOrg"
```

### Cross-Platform Issues & Fixes

**Path Separators**
- Use `os.path.join()` or `pathlib.Path` for portable paths
- Avoid hardcoded forward/backslashes

**Line Endings**
- Set git to handle CRLF: `git config core.autocrlf true`
- Python handles both automatically

**Executable Permissions**
- `chmod +x script.sh` on Unix before running
- Windows doesn't use executable bit (use file extension)

**File Locking**
- Uses `filelock` library for cross-platform support
- Automatic fallback if native locking unavailable

## Known Fixed Issues

### Issue: CSV Field Size Error
**Symptom:** `_csv.Error: field larger than field limit (131072)`
**Cause:** Large directory listing outputs exceed default CSV field limit
**Fixed:** CSV field limit set to 10MB in affected scripts
**Status:** RESOLVED in Phase 2

### Issue: DateTime Compatibility (Python 3.11+)
**Symptom:** `AttributeError: module 'datetime' has no attribute 'UTC'`
**Cause:** `datetime.UTC` removed in Python 3.11
**Fixed:** Changed to `datetime.timezone.utc`
**Status:** RESOLVED - All scripts use timezone.utc

### Issue: ChromeDriver Version Mismatch
**Symptom:** Screenshot capture fails with version mismatch
**Cause:** System Chrome version differs from chromedriver version
**Fixed:** Implemented fallback strategy:
  1. Use local `chromedriver_141` if available
  2. Try webdriver-manager (auto-download)
  3. Fall back to system chromedriver
**Status:** RESOLVED

### Issue: Admin Panel False Positives
**Symptom:** High false positive rate in admin login detection
**Cause:** Catch-all domains returning 200 for all paths
**Fixed:** `smart_filter_screenshots.py` reduces noise by 88%+
**Status:** RESOLVED

### Issue: Cloud Storage Scanner Hanging
**Symptom:** `Other_Buckets.py` appears stuck/deadlocked
**Cause:** Thread pool deadlock under high load (prior to Nov 22)
**Fixed:** Proper ThreadPoolExecutor usage in commit 694381a
**Status:** RESOLVED - Do NOT modify threading logic

### Issue: Auto-Update Conflicts
**Symptom:** `git pull` fails due to local changes
**Cause:** Uncommitted modifications in working directory
**Fixed:** Auto-update now stashes/restores changes safely
**Status:** RESOLVED

### Issue: WHOIS Rate Limiting
**Symptom:** Scanner banned/rate-limited by WHOIS servers
**Cause:** Too many concurrent requests
**Fixed:** Configurable batch sizing and rate limits in config/whois.yml
**Status:** RESOLVED

## Testing

### Run Security Tests
```bash
python3 -m pytest tests/test_security.py -v
```

### Run Unit Tests
```bash
python3 -m pytest tests/ -v --tb=short
```

### Dev Mode Testing
```bash
# Set mode to dev for 10-target cap
export TI_MODE=dev
python3 master_recon.py --organization "TestOrg"
```
