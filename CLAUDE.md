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
```

### Execution Modes
Configure in `config/environment.yml`:
- **dev**: 100 target cap (fast validation, ~5-10 min)
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

The workflow is defined in `workflow_spec.json` with 48 sequential stages organized into 4 phases:

### Phase 1: Target Discovery & Enumeration (Stages 1-10)
- **Target Normalization**: Automatically extracts apex domains (e.g., `www6.slac.edu` → `slac.stanford.edu`)
- **Recon Orchestration**: Parallel subdomain enumeration using subdomz, assetfinder, subfinder, gau
- **DNS Resolution**: Resolves discovered domains to IP addresses
- **HTTP Probing**: Tests web services on discovered hosts
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
  - Manages stage execution with ThreadPoolExecutor
  - Handles script resolution (case-insensitive, path lookup)
  - Supports `--start-stage` for resumption
  - Preflight checks verify all scripts exist before execution

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
  - Example: `recon/modules/subdomz.py`

### State-Persistent Services
- **distributed_whois.py**: Batched WHOIS with JSON state file
- **vnc_scan.py**: VNC scanning with resumption support
- Both use `--state-file` to track progress across runs

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
  - Outputs: Word doc + Interactive HTML appendix

## Configuration Files

All configurations are in `config/`:

- **environment.yml**: Execution mode (dev/quick/production) and target caps
- **recon.yml**: Recon module toggles, workers, delays
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
mode: dev  # Caps at 100 targets

# Run workflow
python3 master_recon.py --organization "TestOrg"
```

## Important Notes

- **All Python scripts use Python 3.13+** (check shebang: `#!/usr/bin/env python3`)
- **Workflow stages are sequential** (no parallel stage execution)
- **Module execution within stages is parallel** (ThreadPoolExecutor with configurable workers)
- **State files enable resumption** for long-running scans (WHOIS, VNC)
- **Baselines are archived** before updates (see `baselines/archive/`)
- **Reports are client-agnostic** - no hardcoded organization names or IPs

## External Dependencies

Required tools (must be in PATH or workspace):
- subdomz (Go binary)
- assetfinder
- subfinder
- gau
- chromedriver (for screenshots)

Python packages managed via pip (see imports in individual scripts).
