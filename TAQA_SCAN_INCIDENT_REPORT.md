# TAQA Threat Intel Scan - Incident Report
**Date:** November 25-26, 2025
**Target:** taqa.com
**Scan Duration:** 13 hours 18 minutes
**Status:** **TERMINATED** due to deadlocked process

---

## Executive Summary

The production-mode threat intelligence scan of taqa.com was terminated after 13+ hours due to a deadlocked cloud storage enumeration process (`Other_Buckets.py`). The workflow successfully completed **Phase 1-2** and most of **Phase 3** before encountering the failure.

**Result:** 147 subdomains discovered, 17 live web hosts identified, extensive intelligence gathered - but final report generation was not completed due to process termination.

---

## Timeline

| Time | Event |
|------|-------|
| 10:51 AM | Workflow started in production mode |
| 10:52 AM | Subdomain enumeration completed (147 domains found - **3.7x improvement** over initial run) |
| 10:53 AM | DNS resolution and HTTP probing completed (17 live hosts) |
| 10:54 AM | WHOIS, typosquat detection, certificate transparency completed |
| 10:55 AM | S3 bucket scanning completed successfully |
| 10:55 AM | **Other_Buckets.py started** (Azure/GCP/DigitalOcean/Wasabi scanning) |
| 12:00 PM+ | Process appeared to be making slow progress |
| 11:55 PM | Process investigation began (13+ hours runtime) |
| 12:06 AM | **DEADLOCK CONFIRMED** - no I/O activity, all threads in futex_wait_queue |
| 12:07 AM | Process terminated with SIGTERM |
| 12:07 AM | Workflow detected failure and continued with remaining stages |
| 12:08 AM | Workflow manually stopped to preserve state and generate report |

---

## Root Cause Analysis

### The Deadlock

**Script:** `Other_Buckets.py` (Multi-cloud storage bucket scanner)
**Duration:** 13 hours 9 minutes (47,494 seconds)
**Exit Code:** -15 (SIGTERM - manually killed)

#### Technical Analysis

1. **Process State:**
   - PID: 8929
   - CPU: 1.9% (constant, minimal activity)
   - Memory: 1.3GB RSS
   - Threads: 100+ threads (from ThreadPoolExecutor with max_workers=100)
   - Thread State: **ALL threads in `futex_wait_queue`** (waiting on locks)

2. **Network Activity:**
   - Open connections: 181 TCP sockets
   - I/O activity: **ZERO bytes transferred in 30-second observation window**
   - I/O counters frozen at: 1,974,154,768 bytes read

3. **Output:**
   - Expected output file: `Other_Buckets_out.csv`
   - Status: **File never created** (13+ hours, no output)
   - Last progress: Scanning 80% (227/283 bucket variants) before hang

#### Why It Happened

The `Other_Buckets.py` script is configured to scan **an extremely large search space**:

```yaml
Configuration from config/cloud_storage.yml:
- max_threads: 100
- max_variants_per_domain: 15
- Enabled providers: 6 (AWS, Azure, GCP, DigitalOcean, Wasabi, + regional variants)
- Domains to scan: 41 (from filtered_domains.txt)
```

**Total URL calculations:**
- 41 domains × 15 variants = **615 bucket names**
- Each bucket checked across:
  - AWS S3 (2 URL patterns)
  - Azure Blob (1 pattern)
  - GCP Storage (2 patterns)
  - DigitalOcean Spaces (6 regions)
  - Wasabi (8 regions)
- **Estimated total URLs: ~11,685 HTTP requests**

With 3-second timeouts, retries, and rate limiting (0.05s delay + jitter), this would take **hours even under ideal conditions**. The deadlock occurred approximately 80% through the scan, suggesting a **thread synchronization issue** or **resource exhaustion**.

**Likely Cause:** Race condition or deadlock in ThreadPoolExecutor when handling 100+ concurrent requests with network timeouts and retry logic.

---

## Data Successfully Collected

Despite the failure, substantial threat intelligence was gathered:

### Phase 1: Reconnaissance & Enumeration ✅

| Metric | Value | Notes |
|--------|-------|-------|
| **Subdomains Discovered** | **147** | 3.7x improvement (vs 40 in test run) |
| **Live Web Hosts** | **17** | HTTP/HTTPS responsive |
| **Unique IP Addresses** | **24** | Harvested for WHOIS |
| **DNS Records Resolved** | 29 | A/AAAA records |

**Tools Used (All Successful):**
- ✅ subdomz
- ✅ assetfinder
- ✅ subfinder
- ✅ gau

**HTTP Status Distribution:**
- 200 OK: 9 hosts
- 302 Redirect: 4 hosts
- 403 Forbidden: 3 hosts
- 404 Not Found: 1 host

### Phase 2: Intelligence Gathering ✅

| Component | Status | Findings |
|-----------|--------|----------|
| **Domain Filtering** | ✅ Complete | 42 of 54 domains kept (77.8%) |
| **Typosquat Detection** | ✅ Complete | **22,126 typosquat candidates** identified |
| **Certificate Transparency** | ✅ Complete | 42 domains analyzed for SSL/TLS certs |
| **Email Security Audit** | ✅ Complete | SPF/DMARC/MX records checked |
| **WHOIS Lookups** | ⚠️ Partial | 12 of 24 IPs completed (batched) |
| **DNS Health Checks** | ✅ Complete | Dead DNS resolver analysis |

**Notable Findings:**
- Multiple dev/staging/UAT environments exposed:
  - `ebsdev-public.taqa.com`
  - `ebsuat.taqa.com`
  - `fusiondev.taqa.com`
  - `elogbookuk-uat.taqa.com`

### Phase 3: Vulnerability Assessment ⚠️ Partial

| Scan Type | Status | Result |
|-----------|--------|--------|
| **S3 Bucket Scanning** | ✅ Complete | 420 bucket variants checked |
| **Azure/GCP/Multi-Cloud** | ❌ **FAILED** | Deadlocked after 13+ hours |
| **Directory Listings** | ⏭️ Skipped | Not reached |
| **Admin Panel Detection** | ⏭️ Skipped | Not reached |
| **Technology Detection** | ⏭️ Skipped | Not reached |
| **Git Exposure** | ⏭️ Skipped | Not reached |
| **VNC Scanning** | ⏭️ Skipped | Not reached |
| **Screenshots** | ⏭️ Skipped | Not reached |

### Phase 4: Reporting ❌ Not Completed

- Change detection: Not run
- Threat context enrichment: Not run
- Final report generation: Not run

---

## Files Generated

All scan outputs are located in: `results/TAQA_20251125_105114/raw_outputs/`

### Key Data Files

```
✅ phase1/targets.json                    (1 normalized target)
✅ phase1/http_probe.csv                  (17 live hosts with tech detection)
✅ phase1/recon_summary.json              (147 subdomains)
✅ phase1_recon_summary.json
✅ Recon_out.csv                          (57 rows of recon data)
✅ domains_only.txt                       (54 unique domains)
✅ resolved.json / DnsResolver_out.csv    (29 resolved IPs)
✅ dns_health.json                        (DNS health metrics)
✅ filtered_domains.txt                   (42 filtered domains)
✅ typo_candidates.csv                    (1.3MB - 22,126 entries)
✅ crt_transparency.csv                   (17KB certificate data)
✅ Email_Security_Audit_out.csv           (SPF/DMARC results)
✅ whois_results.csv                      (Partial - 12 of 24 IPs)
✅ S3_Bucket_Check_out.csv               (31KB - AWS S3 scan results)
✅ all_resolved_ips.txt                   (24 unique IPs)
✅ domain_ip_pairs.txt                    (domain-to-IP mappings)
```

### Missing Files (Due to Termination)

```
❌ Other_Buckets_out.csv                  (Azure/GCP scan - never created)
❌ Dir_Listing_Checker_out.csv
❌ Admin_Login_Enumerator_out.csv
❌ tech_detection_unified.csv
❌ Git_Leak_out.csv
❌ VNC_Checker_out.csv
❌ priority_screenshot_targets.txt
❌ FINAL_REPORT/Threat_Intelligence_Report.docx
❌ FINAL_REPORT/Interactive_Appendix.html
```

---

## Diagnostic Evidence

### Process Diagnostic Report
```
PID: 8929 (Other_Buckets.py)
Runtime: 13:09 hours
CPU: 1.9% (constant)
Memory: 1.3GB RSS
Open network connections: 181

I/O Statistics (30-second monitoring):
  rchar (before): 1,974,154,768 bytes
  rchar (after):  1,974,154,768 bytes
  Change: 0 bytes (NO PROGRESS)

Thread states: ALL threads in futex_wait_queue (DEADLOCKED)
Output file: DOES NOT EXIST after 13+ hours

CONCLUSION: Process is deadlocked, not making progress
```

### Workflow Error Log
```
ERROR:root:Script 'Other_Buckets.py' failed with code -15 after 47494.52s.
ERROR:root:Stage 24 completed with 1 failures.
```

---

## Recommendations

### Immediate Actions

1. **Disable Multi-Cloud Bucket Scanning in Production**
   - Edit `config/cloud_storage.yml`:
     ```yaml
     providers:
       azure_blob:
         enabled: false
       gcp_storage:
         enabled: false
       digitalocean_spaces:
         enabled: false
       wasabi:
         enabled: false
     ```
   - Keep only `aws_s3: enabled: true` (which completed successfully)

2. **Reduce Thread Count**
   - Change `max_threads: 100` → `max_threads: 20`
   - Prevents resource exhaustion and deadlocks

3. **Add Timeout Protection**
   - Implement stage-level timeouts in `master_recon.py`
   - Kill processes that exceed reasonable time limits (e.g., 30 minutes per stage)

### Code Fixes Needed

**File:** `Other_Buckets.py`

**Issues to Address:**
1. **Deadlock Prevention:**
   - Review ThreadPoolExecutor usage with network I/O
   - Add timeout to `executor.map()` calls
   - Implement heartbeat/progress tracking
   - Add graceful shutdown on SIGTERM

2. **Performance Optimization:**
   - Reduce concurrent threads (100 is excessive)
   - Implement exponential backoff on failures
   - Add early termination conditions
   - Consider async/await instead of ThreadPoolExecutor

3. **Progress Reporting:**
   - Write partial results periodically (not just at end)
   - Use tqdm with update frequency limits
   - Log progress to separate file

**Example Fix:**
```python
# Add timeout and partial results
with ThreadPoolExecutor(max_workers=20) as executor:  # Reduced from 100
    futures = []
    partial_results = []

    for task in tasks:
        future = executor.submit(scan_bucket, task)
        futures.append(future)

    # Process results with timeout
    for future in as_completed(futures, timeout=1800):  # 30-min timeout
        try:
            result = future.result(timeout=10)
            partial_results.append(result)

            # Write partial results every 50 items
            if len(partial_results) % 50 == 0:
                write_partial_results(partial_results)
        except TimeoutError:
            logger.warning("Task timeout, skipping...")
```

### Process Improvements

1. **Stage Timeouts:**
   - Add max runtime limits to `workflow_spec.json`:
     ```json
     {
       "id": 24,
       "name": "Phase2_Cloud_Storage_Multi",
       "timeout": 1800,  // 30 minutes max
       "scripts": [...]
     }
     ```

2. **Health Checks:**
   - Implement process health monitoring
   - Kill stages with no I/O activity for > 5 minutes
   - Alert on thread deadlocks

3. **Resume Capability:**
   - Implement state files for all long-running scans
   - Allow resuming from last checkpoint
   - Similar to existing WHOIS/VNC state persistence

---

## Lessons Learned

### What Worked

1. **Tool Installation:** All Go-based recon tools installed successfully and performed well
2. **HTTP Probing:** httpx integration fixed and working perfectly
3. **Modular Recon:** 4-tool parallel enumeration found 3.7x more subdomains
4. **Workflow Resilience:** System detected child process failure and attempted to continue
5. **State Persistence:** WHOIS batching worked as designed

### What Failed

1. **Multi-Cloud Scanning:** Deadlocked after 13+ hours with 100 threads
2. **Lack of Timeouts:** No stage-level timeout protection
3. **No Progress Monitoring:** Couldn't detect hung process until manual investigation
4. **Missing chromedriver:** Screenshots would have failed anyway

### Process Gaps

1. **No automated deadlock detection**
2. **No stage timeout enforcement**
3. **No partial result persistence for long scans**
4. **Insufficient logging of thread states**

---

## Next Steps

### To Complete TAQA Scan

**Option A: Quick Report with Current Data**
```bash
# Generate report from existing data (skip incomplete stages)
cd Reporting_Toolkit
python3 generate_report.py \
  --input-dir "../results/TAQA_20251125_105114/raw_outputs" \
  --output-dir "../results/TAQA_20251125_105114/FINAL_REPORT" \
  --organization "TAQA"
```

**Option B: Re-run with Cloud Scanning Disabled**
```bash
# 1. Disable problematic providers in config/cloud_storage.yml
# 2. Re-run from Stage 25 onward:
python3 master_recon.py \
  --organization "TAQA" \
  --output-dir "results/TAQA_20251125_105114" \
  --start-stage 25
```

### Long-term Fixes

1. Fix `Other_Buckets.py` deadlock issue
2. Implement stage timeouts in `master_recon.py`
3. Add progress monitoring and health checks
4. Install proper chromedriver
5. Add partial result persistence for all long-running scans

---

## Conclusion

The TAQA scan collected **valuable threat intelligence** (147 subdomains, 17 live hosts, 22K typosquat candidates) but was terminated due to a **deadlocked cloud storage scanner**. The failure occurred in a non-critical stage; the core reconnaissance data is intact and usable.

**Impact:** Medium - Report generation incomplete, but raw data is comprehensive.
**Severity:** High - Deadlock issue affects production reliability.
**Priority:** Critical - Fix before next production scan.

---

**Report Generated:** 2025-11-26 00:10 MST
**Prepared By:** Claude Code Automated Analysis
**Diagnostic Files:** `/tmp/taqa_diagnostic.txt`
