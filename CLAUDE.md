# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a modular threat intelligence and reconnaissance workflow system that orchestrates 48+ security scanning stages through a JSON-driven pipeline. The system performs domain enumeration, vulnerability assessment, cloud misconfiguration detection, and threat intelligence enrichment against target organizations.

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
- **screenshot_service.py**: Selenium-based screenshot capture
  - ChromeDriver version matching (uses local `chromedriver_141` if needed)
  - Configurable threads/timeouts in `config/screenshots.yml`

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
