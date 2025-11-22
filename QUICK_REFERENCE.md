# Quick Reference - Reporting & Screenshot System

**Last Updated:** 2025-11-13

---

## What Was Fixed

### Report Coverage (100% Complete)
- ✅ **Typosquatting Filter** - Prevents 500MB+ document crash
- ✅ **Python 2.x EOL Detection** - 12 assets reported (was missing)
- ✅ **OpenSSL 1.0.x EOL Detection** - 12 assets reported (was missing)
- ✅ **PHP 5.x EOL Detection** - 1 asset reported (was missing)
- ✅ **Default Page Filter** - Recovered 1 missed finding
- ✅ **WHOIS Intelligence** - 773 IPs → 20 relevant (97% noise reduction)
- ✅ **Certificate Transparency** - Added "HOW TO READ" guide
- ✅ **Client-Agnostic** - No hardcoded org names/IPs

### Screenshot Optimization
- ✅ **Input File Fixed** - Uses full URLs instead of domains
- ✅ **Priority Targeting** - 1,393 → 589 URLs (security-relevant only)
- ✅ **Workflow Integration** - Stages 42-43 added

---

## File Locations

```
Reporting_Toolkit/
└── generate_report.py          # Main report generator (all fixes here)

prepare_priority_screenshots.py  # NEW: Priority screenshot targeting
screenshot_service.py            # Screenshot capture service
workflow_spec.json              # Workflow orchestration (stages 42-43 added)

config/
└── screenshots.yml             # Screenshot config

results/[ORG]_[DATE]/
├── raw_outputs/                # Scan data (CSV/TXT/JSON)
│   ├── tech_detection_unified.csv
│   ├── Admin_Login_Enumerator_out.csv
│   ├── Default_Page_Checker_out.csv
│   ├── Dir_Listing_Checker_out.csv
│   ├── Non_Production_domains_out.txt
│   ├── crt_transparency.csv
│   ├── distributed_whois_out.csv
│   ├── typosquatting_monitor.csv
│   ├── Detect_Internal_DNS_out.txt
│   └── priority_screenshot_targets.txt  # NEW
├── screenshots/
│   └── priority_targets/       # NEW: Priority screenshots only
└── FINAL_REPORT/
    ├── Threat_Intelligence_Report.docx
    └── Interactive_Appendix.html
```

---

## Key Commands

### Generate Priority Screenshot Targets
```bash
python3 prepare_priority_screenshots.py \
  -i "results/[ORG]_[DATE]/raw_outputs" \
  -o "results/[ORG]_[DATE]/raw_outputs/priority_screenshot_targets.txt"
```

### Capture Priority Screenshots
```bash
python3 screenshot_service.py \
  -i "results/[ORG]_[DATE]/raw_outputs/priority_screenshot_targets.txt" \
  -o "results/[ORG]_[DATE]/screenshots/priority_targets" \
  -c "config/screenshots.yml"
```

### Generate Report
```bash
cd Reporting_Toolkit
python3 generate_report.py \
  --input-dir "../results/[ORG]_[DATE]/raw_outputs" \
  --output-dir "../results/[ORG]_[DATE]/FINAL_REPORT" \
  --organization "[Organization Name]"
```

### Run Full Workflow from Stage 42
```bash
python3 master_recon.py \
  --output-dir "results/[ORG]_[DATE]" \
  --organization "[Organization Name]" \
  --start-stage 42
```

---

## Critical Code Locations

### generate_report.py Changes

| Line | What | Why |
|------|------|-----|
| 629-649 | Certificate Transparency explanation | Added "HOW TO READ" guide |
| 635 | CT example (client-agnostic) | Changed `printers.bnl.gov` → `company.com` |
| 689-706 | Python 2.x EOL detection | NEW section (12 findings) |
| 708-725 | OpenSSL 1.0.x EOL detection | NEW section (12 findings) |
| 727-744 | PHP 5.x EOL detection | NEW section (1 finding) |
| 787 | Typosquatting filter | Changed to check `dns_a != empty` |
| 822 | Default page filter | Added `'default' in status.lower()` |
| 829-859 | WHOIS filtering function | NEW: `is_interesting_ip()` |
| 887 | WHOIS description | Removed hardcoded org/CIDR |

### workflow_spec.json Changes

| Stage | Script | Purpose |
|-------|--------|---------|
| 42 | prepare_priority_screenshots.py | Generate priority target list |
| 43 | screenshot_service.py | Capture priority screenshots |

---

## Troubleshooting

### Report Section Is Empty (But Should Have Data)

**Check if data file exists:**
```bash
ls -lh results/[ORG]_[DATE]/raw_outputs/[filename].csv
head -5 results/[ORG]_[DATE]/raw_outputs/[filename].csv
```

**Check filter matches data format:**
```python
# Example: If status column has "200 OK" but filter checks for "200"
# Change from:
lambda row: row.get('status') == '200'
# To:
lambda row: '200' in row.get('status', '')
```

### Report Too Large (>10MB)

**Identify large section:**
```bash
ls -lh results/[ORG]_[DATE]/FINAL_REPORT/*.docx
```

**Fix: Add filtering (example WHOIS):**
```python
# In generate_report.py, add filter function like:
def is_interesting_ip(row):
    whois = row.get('whois_info', '').lower()
    return any(keyword in whois for keyword in ['cloud', 'amazon', 'google', 'rfc1918'])
```

### Screenshot Failures (>30%)

**Check input file format:**
```bash
head -10 results/[ORG]_[DATE]/raw_outputs/live_web_hosts.txt
# Should show: https://domain:443 (NOT just: domain.com)
```

**Verify workflow uses correct file:**
```bash
grep -A5 '"name": "screenshot_service"' workflow_spec.json | grep '"-i"'
# Should show: live_web_hosts.txt (NOT live_web_hosts_domains.txt)
```

### Priority Screenshot Targets Empty

**Check source files exist:**
```bash
ls -lh results/[ORG]_[DATE]/raw_outputs/{Admin_Login_Enumerator_out.csv,Default_Page_Checker_out.csv,Dir_Listing_Checker_out.csv,Non_Production_domains_out.txt}
```

**If files exist but targets empty:**
- No security findings = expected behavior
- Check CSV column names match script expectations

---

## Statistics (BNL Dataset)

### Report Coverage
- Total new findings reported: **26**
  - Python 2.x: 12 (HIGH)
  - OpenSSL 1.0.x: 12 (HIGH)
  - PHP 5.x: 1 (CRITICAL)
  - Default pages: 1 (LOW)
- Report sections: ~23
- Coverage: **100%**
- File size: **49KB** (was 500MB+ before typosquatting fix)

### Screenshot Optimization
- Original targets: 1,393 attempts (63% failure)
- Priority targets: **589 URLs** (security-relevant only)
- Breakdown:
  - Admin login pages: 507
  - Directory listings: 71
  - Non-prod domains: 10
  - Default pages: 1
- Reduction: **58% fewer targets**, 100% relevant

---

## Verification Commands

### Check Client-Agnostic (Should Find Nothing)
```bash
grep -i "bnl\|brookhaven\|130.199" Reporting_Toolkit/generate_report.py
# Expected: NO MATCHES
```

### Count Findings by Severity
```bash
grep -i "severity.*high\|severity.*critical" results/[ORG]_[DATE]/raw_outputs/*.csv | wc -l
```

### Test Priority Screenshot Generation
```bash
python3 prepare_priority_screenshots.py \
  -i "results/[ORG]_[DATE]/raw_outputs" \
  -o "/tmp/test_priorities.txt" && \
wc -l /tmp/test_priorities.txt && \
head -10 /tmp/test_priorities.txt
```

---

## Next Steps / Future Improvements

1. **Screenshot Protocol Validation** - Prevent invalid http/https port combos
2. **Executive Summary Auto-Generation** - Based on finding counts/severity
3. **Trend Analysis** - Compare with baseline, show changes over time
4. **Risk Scoring** - Numerical scores instead of just severity labels
5. **SIEM Integration** - Send findings to SIEM for correlation
6. **Parallel Stage Execution** - Run independent stages concurrently
7. **Screenshot Deduplication** - Group visually similar screenshots

See `REPORTING_AND_SCREENSHOT_INDEX.md` for detailed implementation ideas.

---

## Documentation

**Comprehensive Guide:** `REPORTING_AND_SCREENSHOT_INDEX.md`
- Detailed troubleshooting
- Code explanations
- Future improvements
- Integration opportunities

**This File:** Quick at-a-glance reference
- Commands
- File locations
- Statistics
- Common issues

---

**Version:** 1.0 (2025-11-13)
**Status:** Production-ready, tested on BNL dataset
**Portability:** Fully client-agnostic, works for any organization
