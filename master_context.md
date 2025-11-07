# Master Context – Threat Intel Workflow Revamp
_Last updated: 2025-11-06_

## Vision & Success Criteria
- Deliver a WOW-grade, end-to-end threat intelligence orchestration that feels polished, fast, and reliable.
- Preserve the simple operator experience (`run.sh` → `targets.txt` → org prompt) while modernizing everything behind the scenes.
- Rebuild the workflow as modular phases with clear inputs/outputs so each script can be tested, swapped, or parallelized independently.
- Provide auditable change tracking (via git) and living documentation to keep the team aligned as we iterate.

## Current Pipeline Snapshot
1. **Bootstrap (`run.sh` + `setup.sh`)** installs dependencies, ensures Chromium driver, activates `.venv`, runs preflight on `workflow_spec.json`.
2. **Slimmed workflow_spec (20 stages)** focuses on recon → DNS/filtering → web exposure → reporting, all under `results/<ORG>_<TS>/raw_outputs`.
3. **Key scripts in use** (see inventory below) write CSV/TXT artifacts under `raw_outputs`; later stages consume those files.
4. **Gaps**: WHOIS enrichment never runs (no IP list), reporting fails on relative paths, many legacy checks (ports, takeover variants, default-page, fallback logic) are not wired in.

## Script Inventory (Primary workspace)
| Script | Purpose (current/expected) | Key Inputs | Outputs |
| --- | --- | --- | --- |
| `Recon1.py` | Subdomain enumeration (SubDomz, assetfinder, subfinder, gau) + DNS resolve + optional HTTP probe | `targets.txt` entries | `recon_outputs/<domain>/*.txt`, per-domain `*_recon.csv`, `all_resolved_ips.txt` (needs fix) |
| `collect_recon.py` | Merge per-domain recon CSVs, produce master list and `domains_only.txt` | `raw_outputs/recon_outputs/**` | `Recon_out.csv`, `domains_only.txt` |
| `consolidate_ips.py` | Aggregate IPs from per-domain files (expects `resolved_ips.txt`) | `recon_outputs/*/resolved_ips.txt` | `all_resolved_ips.txt` (currently empty) |
| `domain_filter.py` | Apply heuristics to domains_only to cut obvious noise | `domains_only.txt` | `filtered_domains.csv` |
| `extract_column.py` | Column extractor helper | CSV path + column name | TXT list |
| `DNS_Records_Check.py` | Query DNS records for domains | `domains_only.txt` | `DNS_Records_Check_out.csv` |
| `Detect_Internal_DNS.py` | Flag internal DNS leakage | `filtered_domains.txt` | `Detect_Internal_DNS_out.txt` |
| `Email_Security_Audit.py` | MX/SPF/DMARC review | `filtered_domains.txt` | `Email_Security_Audit_out.csv` |
| `S3_Bucket_Check.py` / `Bucket_To_URL.py` | Find exposed buckets + map to URLs | `domains_only.txt` / bucket results | CSV outputs |
| `web_host_discovery.py` | Turn recon output into live web hosts (needs consistent inputs) | `Recon_out.csv` | `live_web_hosts.txt` |
| `prepare_web_asset_lists.py` | Split live hosts into host/domain lists | `Recon_out.csv`, `live_web_hosts.txt` | `live_web_hosts_domains.txt`, etc. |
| `BrowserFingerprint_JSLibrary_Checkier.py`, `redirectissuefinder.py`, `Admin_Login_Enumerator.py`, `Git_Leak.py`, `SSL_TLS_Cert_Check.py`, `WAF_Checker.py`, `Cloud_Misconfig.py`, `Subdomain_Takeover*_*.py`, `ScreenShotterQuiet.py`, `Debug_paths.py` | Various Phase 3 web exposure checks | Live host/domain files | Tool-specific CSV/TXT outputs |
| `merge_whois.py`, `Reporting_Toolkit/*` | Combine recon + WHOIS + render report | `Recon_out.csv`, `whois_results.csv` | `Recon_out_enriched.csv`, PDF/HTML report |

_(See repository root for dozens of additional scripts currently unused; notable legacy ones listed under “Legacy Features” below.)_

## Legacy Features Worth Reintroducing/Modernizing
- `Old _Files/workflow_spec21.json` enumerates 50+ stages including: fallback staging, `dnstwister_whois*`, `DnsResolver2` → `transform_dns_output`, `Default_Page_Checker`, `Dir_Listing_Checker`, `tech_checker`, `Passive_Debug_Path_Scraper`, `Open_Ports_1`, `VNC_Checker`, extended screenshotters, `merge_outputs.py`, `enumerate_results.py`.
- Deprecated script folder contains `Passive_Debug_Path_Scraper.py`; other helpers (e.g., `dnstwister_whois_old _version.py`) still compile but need refactors.
- Many stages wrote to flat `outputs/*.csv`; we’ll re-map them into the per-run structure while auditing necessity and cost/benefit.

## Proposed Next-Gen Architecture
### Phase 0 – Bootstrap & Config
- Keep `run.sh` UX, but turn `workflow_spec.json` into a **generated artifact** (derived from a higher-level YAML/py config) so edits are consistent.
- Introduce `config/` for tool paths, API keys, tuning knobs (threads, timeouts) with sane defaults.

### Phase 1 – Recon & Enumeration
1. **Target ingestion** (`targets.txt`, optional JSON w/ metadata).
2. **Recon orchestrator** (`Recon1.py` refactor): plug-in modules for each provider (SubDomz, assetfinder, subfinder, amass, gau, custom). Standardize outputs:
   - `recon_outputs/<domain>/sources/*.txt`
   - `recon_outputs/<domain>/aggregated_domains.txt`
   - `recon_outputs/<domain>/resolved.json` (domain→IPs array)
3. **IP harvesting**: replace `consolidate_ips.py` with logic that walks `resolved.json` to produce `all_resolved_ips.txt` and `domain_ip_pairs.txt`.
4. **Stateful WHOIS batches** should then have real input and write `whois_results.csv` incrementally.

### Phase 2 – Domain Intelligence & Filtering
- **Domain hygiene pipeline**: `collect_recon` → `domain_filter` → `filtered_domains.(csv/txt)` consolidated in one module with YAML-defined filters (keywords, TLD allow/block lists).
- **DNS deep dive**: unify `DNS_Records_Check`, `DnsResolver2`, `Dead_DNS_Checker/Resolver`, `Detect_Internal_DNS` into `dns_suite.py` that emits structured JSON + CSV for each check.
- **Email/Supply-chain**: keep `Email_Security_Audit`, add SPF/DMARC parsing improvements and optional MX reputation checks.
- **Typosquat & Dnstwister**: resurrect logic from `dnstwister_whois_old _version.py`, but move to asynchronous HTTP API mode and enforce output schema.

### Phase 3 – Surface Asset Discovery & Exposure Mapping
- **Web asset preparation**: `web_host_discovery` + `prepare_web_asset_lists` combined into `web_inventory.py` that produces `live_hosts.json`, `live_hosts_domains.txt`, `domain_ip_pairs.txt`.
- **Service/Port scans**: modernize `Open_Ports_1.py`, integrate with `nmap`/`naabu` results; store per-host service banners.
- **Exposure analyzers**: update/replace the legacy scripts (Default page, dir listing, Git leak, admin login, JS fingerprint, WAF, SSL, etc.) to share a common input format and concurrency pool. Provide per-tool config toggles.
- **Cloud & storage checks**: extend `S3_Bucket_Check` to multi-cloud (GCP/Azure), add `Other_Buckets.py` logic.
- **Screenshot/visual fingerprinting**: wrap `ScreenShotterQuiet.py`, `screenshot_websites.py`, `unified_screenshotter.py` under a single controller with retry + metadata.

### Phase 4 – Aggregation, Analytics & Reporting
- **Data lake**: standardize all outputs into `raw_outputs/<phase>/<tool>.{csv,json}` plus a single SQLite/Parquet for cross-tool correlation.
- **Merge layers**: `merge_whois.py`, `merge_outputs.py`, `enumerate_results.py` should be consolidated into `report_builder.py` that:
  - Joins recon + DNS + WHOIS + exposure data.
  - Scores findings by severity/confidence.
  - Exports CSV, JSON, and feed data for Reporting Toolkit.
- **Reporting Toolkit**: fix path handling (always pass absolute `Recon_out_enriched.csv`), add templated sections (exec summary, key risks, artifacts).

## Data Flow & Artifacts (per run)
```
results/<ORG>_<TS>/
  raw_outputs/
    phase1_recon/
      recon_outputs/<domain>/...
      all_domains.txt
      all_resolved_ips.txt
      domain_ip_pairs.txt
    phase2_dns/
      dns_records.csv
      dns_health.json
      email_security.csv
      typosquat.csv
    phase3_exposure/
      live_hosts.txt
      live_hosts_domains.txt
      <tool>_out.csv
    enrichment/
      whois_results.csv
      recon_enriched.csv
  processed/
    dashboards/
    report_assets/
  logs/
    *.log
```

## Implementation Roadmap
1. **Discovery & Documentation (current step)**
   - Inventory scripts (done).
   - Decide “must keep vs retire” per legacy tool.
   - Document dependencies/APIs per script.
2. **Architecture & Spec Generator**
   - Define new stage list (YAML) → auto-generate `workflow_spec.json` so we can version the high-level plan.
   - Map each stage to script refactor requirements.
3. **Core Refactors**
   - `Recon1.py` → module-based enumerator with proper outputs.
   - Replace `consolidate_ips.py` & fix WHOIS chain.
   - Build unified DNS+filter module.
4. **Exposure Toolkit Refresh**
   - Modernize/merge web scanners; add concurrency + error budgets.
   - Introduce service/port scanning.
5. **Data Store + Reporting**
   - Standard schema, central merge, fix Reporting Toolkit path usage.
6. **Polish & Automation**
   - Add retries, health checks, and summary dashboards.
   - Build test suites per module.

Each phase ends with committed code + updated docs + regression test run.

## Version Control & Change Tracking
- Initialize git in repo root: `git init && git add . && git commit -m "baseline before revamp"`.
- Workflow:
  1. Create branch per feature (`git checkout -b feature/recon-refactor`).
  2. Make changes, run tests, `git add ...`, `git commit -m "Describe change"`.
  3. Merge back to main once reviewed (can be simple `git merge` for now).
- For non-git backups, we can mirror key scripts into `history/` with timestamped copies, but git is strongly recommended for diffing/reverts.

## Next Actions
1. Decide which legacy scripts are revivable vs. archived (make a spreadsheet or markdown table).
2. Draft the new high-level stage spec (phases + script mappings) using this context.
3. Stand up git so every subsequent change is tracked automatically.
4. Begin with Recon/IP/WHOIS chain fixes, since most downstream failures stem from that gap.

---
This file should be updated whenever we adjust the plan, implement a milestone, or add/remix scripts so everyone stays on the same page.

## Live Collaboration Notes (updated at 2025-11-07 00:19:04 UTC)
- Keep `master_context.md` as the single source of truth; update it after every prompt.
- Use the file as roadmap + context handoff when chat context resets; carry over ongoing instructions.

## Rebuild Kickoff (2025-11-07 00:20:27 UTC)
### Immediate Objectives
1. **Script Capability Audit** – enumerate every primary + legacy script, tag with phase, required inputs, outputs, deps, and status (keep/refactor/archive).
2. **Workflow Blueprint** – design the future stage list (Phase 0-4) with clear contracts (input file, output file, format) and execution order so we can auto-generate workflow_spec.json.
3. **Refactor Workstreams** – break the rebuild into parallel-friendly tracks (Recon core, DNS/intel, Exposure stack, Data/Reporting) with deliverables + owners.
4. **Change Control** – initialize git, capture baseline commit, and document branch strategy in this file so every change is tracked.

### Working Notes
- Use this section to log progress on the four objectives; update entries as we complete each audit or spec draft.
- Next action: start Script Capability Audit (pull metadata via ls/grep + manual review).

### Guiding Principle (2025-11-07 00:22:55 UTC)
- Rebuild every retained script to achieve equal or better functionality while enforcing consistent input/output contracts (shared schemas, standardized file naming).
- Prefer refactoring existing scripts that already encapsulate APIs/credentials rather than rewriting from scratch; focus engineering effort on uniform wrappers, logging, and error handling.
- Treat this directive as standing order for all future development (update after each prompt).

### Operating Posture (2025-11-07 00:24:51 UTC)
- Maintain a quiet/low-traffic footprint across all external-facing modules; throttle concurrency, randomize intervals, and honor robots/opt-outs where applicable.
- Passive-first mindset: prefer OSINT, cached, or API-sourced data before active probing; when active checks are required, stagger requests and use customer-approved IP ranges/headers.
- Balance stealth with efficiency by batching lookups, caching results, and avoiding redundant scans across stages.

### Script Capability Audit – Batch 1 (2025-11-07 00:27:45 UTC)
| Script | Category | Current Role | Status | Notes |
| --- | --- | --- | --- | --- |
| Recon1.py | Recon & Enumeration | Aggregates subdomain sources, resolves, optional httpx | Refactor (modularize) | Enforce structured outputs (`resolved.json`, IP harvesting), add throttling knobs. |
| collect_recon.py | Data Processing | Merges per-domain recon CSVs, builds `domains_only.txt` | Refactor (integrate) | Fold into recon pipeline; ensure schema validation & deduping. |
| consolidate_ips.py | Data Processing | Searches for `resolved_ips.txt` to build `all_resolved_ips.txt` | Replace | Needs redesign to read new recon outputs; currently produces empty files. |
| domain_filter.py | Domain Intelligence | Heuristic filtering of domains | Refactor | Convert to config-driven filters; emit tagged decisions. |
| DNS_Records_Check.py | DNS Suite | Queries DNS records for each domain | Refactor | Combine with `DnsResolver2`/`Dead_*` into unified `dns_suite`. |
| DnsResolver2.py | DNS Suite | Reliable resolver w/ CSV output | Refactor | Centralize resolver logic, share cache with other DNS modules. |
| Dead_DNS_Checker.py | DNS Suite | Checks for dead DNS entries | Candidates for merge | Probably lives inside new DNS health module. |
| Dead_DNS_Resolver.py | DNS Suite | Resolves dead entries | Merge | Same as above. |
| Detect_Internal_DNS.py | DNS/Exposure | Flags internal domains in DNS output | Keep + polish | Needs better reporting + JSON output for cross-tool use. |
| Email_Security_Audit.py | DNS/Email | MX/SPF/DMARC analysis | Refactor | Normalize output schema; add throttling + logging. |
| S3_Bucket_Check.py | Cloud Storage | Probes for public S3 buckets per domain | Refactor | Expand to multi-cloud, add passive checks before active probing. |
| Bucket_To_URL.py | Cloud Storage | Converts bucket names to URLs | Keep | Minor clean-up; ensure consistent file locations. |

### Script Capability Audit – Batch 2 (2025-11-07 00:29:40 UTC)
| Script | Category | Current Role | Status | Notes |
| --- | --- | --- | --- | --- |
| web_host_discovery.py | Web Inventory | Builds live web host list from recon CSV | Refactor | Merge with `prepare_web_asset_lists`; enforce shared schema. |
| prepare_web_asset_lists.py | Web Inventory | Splits live hosts into domains/targets | Merge | Combine into `web_inventory.py` with JSON outputs. |
| Admin_Login_Enumerator.py | Web Exposure | Probes admin portals | Refactor | Add rate limiting, authentication handling, structured results. |
| Git_Leak.py | Web Exposure | Checks for exposed `.git` directories | Refactor | Provide passively gathered hints before active hits; normalize output. |
| BrowserFingerprint_JSLibrary_Checkier.py | Web Exposure | JS lib fingerprinting | Refactor | Rename for clarity, share HTTP session pool, output JSON. |
| redirectissuefinder.py | Web Exposure | Detects redirect issues | Keep + Polish | Align inputs and logging with new web inventory. |
| SSL_TLS_Cert_Check.py | Web Exposure | SSL/TLS inspection | Refactor | Add passive cert transparency ingestion; ensure minimal active probes. |
| WAF_Checker.py | Web Exposure | Identifies WAF signatures | Refactor | Use shared HTTP client + allow custom header profiles. |
| Cloud_Misconfig.py | Cloud Exposure | Pairs domains/IPs to misconfigs | Refactor | Needs real domain→IP input + multi-cloud support. |
| Subdomain_Takeover_Checker.py / Subdomain_Takeover2.py | Exposure | Detects takeover candidates | Refactor | Consolidate into single module w/ provider-specific plug-ins. |
| ScreenShotterQuiet.py / unified_screenshotter.py / screenshot_websites.py | Exposure UX | Capture visuals | Consolidate | Build one screenshot service w/ queue + metadata. |
| Debug_paths.py | Exposure Support | Processes debug-path findings | Keep + Polish | Ensure it consumes JSON and emits per-host artifacts. |

### Script Capability Audit – Batch 3 (2025-11-07 00:30:49 UTC)
| Script | Category | Current Role | Status | Notes |
| --- | --- | --- | --- | --- |
| Default_Page_Checker.py | Web Exposure | Flags default/placeholder pages | Refactor | Integrate with new HTTP client + scoring engine. |
| Dir_Listing_Checker.py | Web Exposure | Detects directory listing | Refactor | Share crawler logic; add passive hints first. |
| tech_checker.py | Fingerprinting | Identifies tech stack | Refactor | Consolidate with JS fingerprint + Wappalyzer-style logic. |
| Non_Production_domains.py | Classification | Splits prod vs non-prod | Refactor | Use tagging pipeline; emit JSON for report weighting. |
| Open_Ports_1.py / Open_Ports 1.py | Port Scanning | Basic port probes | Replace | Build modern port/service module (naabu/nmap wrappers) w/ quiet mode. |
| VNC_Checker.py | Service Exposure | Checks VNC endpoints | Refactor | Fold into service scanner with safe banner grabs. |
| Cloud_Misconfig helpers (Other_Buckets.py, CRT_transparency.py) | Cloud/OSINT | Additional data sources | Review | Evaluate for integration into passive data gathering stack. |

### Script Capability Audit – Batch 4 (2025-11-07 00:30:55 UTC)
| Script | Category | Current Role | Status | Notes |
| --- | --- | --- | --- | --- |
| merge_whois.py | Data Enrichment | Joins recon + WHOIS CSVs | Refactor | Needs real WHOIS input, pandas best practices, JSON export. |
| merge_outputs.py | Data Aggregation | Legacy final merge | Replace | Roll into new `report_builder`. |
| enumerate_results.py | Reporting | Generates JSON summary | Refactor | Should consume unified data store + support severity scoring. |
| Reporting_Toolkit/* | Reporting UX | Generates client deliverables | Refactor | Fix path handling, modularize templates, enable CLI flags. |
| move_to_processed.py / launcher.py | Workflow Utility | Housekeeping helpers | Review | Determine if needed in new pipeline or replaced by orchestrator. |
| update_workflow_spec.py | Workflow Utility | Possibly script to adjust spec | Review | Consider replacing with new spec generator. |

### Script Capability Audit – Batch 5 (Legacy/Deprecated) (2025-11-07 00:31:02 UTC)
| Script | Category | Role | Status | Notes |
| --- | --- | --- | --- | --- |
| dnstwister_whois_old _version.py | Typosquat | Legacy WHOIS + typosquat generator | Extract Logic | Port core algorithms into new typosquat module; retire file. |
| Passive_Debug_Path_Scraper.py (deprecated_scripts) | Exposure Support | Parses passive data feeds | Evaluate | If still valuable, fold into new debug-path workflow. |
| Recon1_old.py / stage2_recon.py | Recon | Old enumerators | Archive | Use as reference only; new Recon pipeline replaces them. |
| redirectissuefinder1.py | Web Exposure | Older variant | Archive | Keep single maintained version. |
| old_results_wipe1.py / clean_output_old*.py / transform_dns_output_old2.py / Debug_paths_old*.py | Utilities | Outdated helpers | Archive | Use for reference when rebuilding functionality. |
| multitwist.py / shodan_parser.py / shodan_search.py / legacy_shodan_adapter.py | Enrichment | Various Shodan/DNSTwister tools | Evaluate | Decide if Shodan integration stays; if yes, wrap cleanly with API handling + quiet mode. |
| CRT_transparency.py | OSINT | Pulls CT logs | Keep (passive) | Move under OSINT modules; ensure caching + dedupe. |
| Resolve_IPs_* / Other misc | Utilities | Address resolution helpers | Evaluate | Consolidate into DNS/IP service. |

## Workflow Blueprint Draft (2025-11-07 00:32:17 UTC)
### Phase 0 – Bootstrap & Governance
1. `run.sh` (existing) – retain UX but add config discovery (`config/*.yml`), environment validation, and spec generation (`workflow_spec_builder.py`).
2. `setup.sh` – keep idempotent installs, add module toggles, extra telemetry deps.
3. Version control check – warn if git isn’t initialized; encourage commit after each milestone.

### Phase 1 – Reconnaissance & Asset Discovery
1. **Target Intake**: `targets.txt` → `raw_outputs/phase1/targets.json` (normalized).
2. **Recon Aggregator (`ReconOrchestrator`)**: modular calls to SubDomz, assetfinder, subfinder, amass (optional), gau, etc.; outputs `recon_outputs/<domain>/sources/*.txt` + `aggregated_domains.txt`.
3. **Resolution & HTTP Probe**: produce `resolved.json`, `resolved_ips.txt`, `http_probe.csv` with standardized schema.
4. **IP Consolidation**: derive `all_resolved_ips.txt`, `domain_ip_pairs.txt` for WHOIS/exposure.

### Phase 2 – Domain Intelligence & DNS/Email Hygiene
1. **Domain Filtering Pipeline**: config-driven heuristics → `filtered_domains.csv/txt` with decision metadata.
2. **DNS Suite**: unified resolver collecting records, detecting dead/internal DNS → `dns_records.csv`, `dns_health.json`, `internal_dns_findings.csv`.
3. **Email Security**: MX/SPF/DMARC analysis with passive enrichments → `email_security.csv`.
4. **Typosquat & Brand Monitoring**: refactor dnstwister logic → `typo_candidates.csv`, `typo_whois.json`.
5. **Cloud Storage OSINT**: passive-first bucket discovery → `cloud_storage_candidates.csv`.

### Phase 3 – Exposure & Service Analysis
1. **Web Inventory Builder**: merge web_host_discovery + prepare_web_asset_lists → `live_hosts.json/txt`, `live_host_domains.txt`.
2. **Service & Port Scanner**: quiet naabu/nmap wrapper → `service_map.json`.
3. **Web Exposure Toolkit**: consolidated worker pool for admin login, git leak, default pages, dir listing, JS fingerprint, redirect checks, SSL/TLS, WAF, cloud misconfig, takeover; each writes `<tool>_findings.csv/json`.
4. **Screenshot & Evidence**: single screenshot service with queue → `screenshots/<host>.png`, `screenshots/index.json`.
5. **Specialized Checks**: VNC/service banners integrated into service scanner outputs.

### Phase 4 – Enrichment, Correlation & Reporting
1. **WHOIS Enrichment**: refactored distributed_whois consumes `all_resolved_ips.txt`, writes `whois_results.csv`.
2. **Data Lake Assembly**: convert CSVs to SQLite/Parquet via `data_assembler.py`; enforce schema validation.
3. **Correlation/Scoring Engine**: `report_builder.py` merges Recon/DNS/Email/Exposure/WHOIS, applies severity scoring + quiet posture flags; outputs `Recon_out_enriched.csv`, `findings.json`, `summary_stats.json`.
4. **Reporting Toolkit Integration**: pass absolute paths to `Reporting_Toolkit`, produce PDF/HTML + artifact bundle.

### Cross-Cutting Concerns
- Quiet mode controls (threads, jitter, schedule) centralized in config.
- Structured logging per module (`logs/<phase>/<module>.log`).
- Retry/error taxonomy shared across modules.
- Test coverage: unit tests per module + integration tests per phase.

### Blueprint Next Steps
1. Map audited scripts to these phases (keep/refactor/archive).
2. Draft YAML stage spec for generator (includes inputs/outputs, dependencies).
3. Sequence implementation roadmap (Recon core first, then DNS/email, exposure, reporting).

### Script ↔ Phase Mapping (2025-11-07 00:33:19 UTC)
| Script | Blueprint Phase | Action | Notes |
| --- | --- | --- | --- |
| run.sh / setup.sh | Phase 0 | Keep + enhance | Add config discovery, spec builder integration, VC checks. |
| workflow_spec_generator.py (new) | Phase 0 | Build | Generates workflow_spec from YAML blueprint. |
| Recon1.py (→ ReconOrchestrator) | Phase 1 | Major refactor | Modularize sources, structured outputs. |
| collect_recon.py | Phase 1 | Fold into Recon orchestrator | Domain aggregation handled centrally. |
| consolidate_ips.py | Phase 1 | Replace | New IP harvesting pipeline writes domain_ip_pairs + all_resolved_ips. |
| domain_filter.py | Phase 2 | Refactor | Config-driven filters + metadata outputs. |
| DNS_Records_Check.py / DnsResolver2.py / Dead_* / Detect_Internal_DNS.py | Phase 2 | Merge into DNS suite | Shared resolver, outputs to csv/json. |
| Email_Security_Audit.py | Phase 2 | Refactor | Structured output + quiet posture. |
| dnstwister_whois_old version | Phase 2 | Extract logic | Build new typosquat module. |
| S3_Bucket_Check.py / Bucket_To_URL.py / Other_Buckets.py | Phase 2/3 | Refactor | Passive-first discovery, multi-cloud support. |
| web_host_discovery.py + prepare_web_asset_lists.py | Phase 3 | Merge | New web_inventory.py. |
| Open_Ports_* / VNC_Checker.py | Phase 3 | Replace | Integrated service scanner. |
| Admin_Login_Enumerator.py … (web exposure suite) | Phase 3 | Refactor | Unified exposure toolkit with shared I/O. |
| ScreenShotter suite | Phase 3 | Consolidate | One screenshot service + queue. |
| Debug_paths.py / Passive_Debug_Path_Scraper.py | Phase 3 | Evaluate + integrate | Provide passive debug path ingestion/reporting. |
| distributed_whois.py | Phase 4 | Refactor | Incremental batches, quiet delays, JSON outputs. |
| merge_whois.py / merge_outputs.py / enumerate_results.py | Phase 4 | Merge | New report_builder.py. |
| Reporting_Toolkit | Phase 4 | Refactor | Accept absolute paths, modular templates. |
| data_assembler.py (new) | Phase 4 | Build | Convert CSV outputs to SQLite/Parquet. |
| move_to_processed.py / launcher.py / update_workflow_spec.py | Phase 0/4 | Review | Keep if needed after new orchestration. |

### Workflow Spec Outline (2025-11-07 00:36:37 UTC)
```yaml
workflow:
  phases:
    - id: 0
      name: Bootstrap
      stages:
        - name: Setup
          scripts:
            - run.sh --generate-spec
            - setup.sh
        - name: Spec_Builder
          scripts:
            - workflow_spec_builder.py --config config/pipeline.yml --output workflow_spec.json
    - id: 1
      name: Recon_Discovery
      stages:
        - name: Target_Intake
          scripts:
            - target_normalizer.py --input targets.txt --output {output_dir}/raw_outputs/phase1/targets.json
        - name: Recon_Aggregator
          scripts:
            - ReconOrchestrator.py --config config/recon.yml --targets {output_dir}/raw_outputs/phase1/targets.json --output {output_dir}/raw_outputs/recon_outputs
        - name: Resolution_and_HTTP
          scripts:
            - resolver.py --input {output_dir}/raw_outputs/recon_outputs --output {output_dir}/raw_outputs/phase1/resolution
        - name: IP_Consolidation
          scripts:
            - ip_harvester.py --input {output_dir}/raw_outputs/phase1/resolution --ips {output_dir}/raw_outputs/all_resolved_ips.txt --pairs {output_dir}/raw_outputs/domain_ip_pairs.txt
    - id: 2
      name: Domain_Intelligence
      stages:
        - name: Domain_Filter
          scripts:
            - domain_filter.py --input {output_dir}/raw_outputs/domains_only.txt --config config/domain_filters.yml --output {output_dir}/raw_outputs/filtered_domains.csv
        - name: DNS_Suite
          scripts:
            - dns_suite.py --domains {output_dir}/raw_outputs/filtered_domains.txt --records {output_dir}/raw_outputs/dns_records.csv --health {output_dir}/raw_outputs/dns_health.json
        - name: Email_Security
          scripts:
            - Email_Security_Audit.py --input {output_dir}/raw_outputs/filtered_domains.txt --output {output_dir}/raw_outputs/email_security.csv
        - name: Typosquat_Monitor
          scripts:
            - typosquat_monitor.py --input {output_dir}/raw_outputs/filtered_domains.txt --output {output_dir}/raw_outputs/typo_candidates.csv
        - name: Cloud_OSINT
          scripts:
            - cloud_storage_osint.py --input {output_dir}/raw_outputs/filtered_domains.txt --output {output_dir}/raw_outputs/cloud_storage_candidates.csv
    - id: 3
      name: Exposure_and_Service
      stages:
        - name: Web_Inventory
          scripts:
            - web_inventory.py --recon {output_dir}/raw_outputs/Recon_out.csv --output-dir {output_dir}/raw_outputs
        - name: Service_Scan
          scripts:
            - service_scanner.py --hosts {output_dir}/raw_outputs/live_hosts.txt --output {output_dir}/raw_outputs/service_map.json
        - name: Exposure_Toolkit
          scripts:
            - exposure_runner.py --hosts {output_dir}/raw_outputs/live_hosts.txt --config config/exposure.yml --output-dir {output_dir}/raw_outputs
        - name: Screenshot_Service
          scripts:
            - screenshot_service.py --hosts {output_dir}/raw_outputs/live_hosts.txt --output {output_dir}/screenshots
    - id: 4
      name: Enrichment_and_Reporting
      stages:
        - name: WHOIS_Enrichment
          scripts:
            - distributed_whois.py --input {output_dir}/raw_outputs/all_resolved_ips.txt --output {output_dir}/raw_outputs/whois_results.csv --state {output_dir}/raw_outputs/whois_state.json
        - name: Data_Assembly
          scripts:
            - data_assembler.py --raw {output_dir}/raw_outputs --sqlite {output_dir}/processed/data.db
        - name: Report_Builder
          scripts:
            - report_builder.py --raw {output_dir}/raw_outputs --whois {output_dir}/raw_outputs/whois_results.csv --output {output_dir}/raw_outputs/Recon_out_enriched.csv
        - name: Reporting_Toolkit
          scripts:
            - Reporting_Toolkit/generate_threat_report.sh {output_dir}/raw_outputs/Recon_out_enriched.csv
```

### Phase 1 Execution Plan – Recon & IP Chain (2025-11-07 00:38:19 UTC)
1. **Recon Module Decomposition**
   - Create `recon/modules/` package; each enumerator (SubDomz, assetfinder, subfinder, amass, gau, custom) implements `run(domain, config) -> list[str]` with shared retry/throttle wrappers.
   - Central `ReconOrchestrator.py` loads enabled modules from `config/recon.yml`, executes sequentially or with bounded concurrency, and writes per-module raw outputs under `recon_outputs/<domain>/sources/<module>.txt`.

2. **Data Normalization**
   - Aggregated domains per target stored in JSON: `recon_outputs/<domain>/aggregated_domains.json` (fields: `domain`, `sources`, `first_seen`, `confidence`).
   - `all_domains.txt` / `*_recon.csv` derived from this JSON; CSV schema = `domain,source,module,timestamp`.

3. **Resolution Pipeline**
   - New `resolver.py` ingests aggregated JSON, batches DNS queries with jitter, caches answers, and writes `resolved.json` (domain→{"ips": [...], "metadata": {...}}).
   - Optionally kicks off `http_probe.py` (refactored httpx wrapper) producing `http_probe.csv` with `url,status,title,response_hash`.

4. **IP Harvesting**
   - `ip_harvester.py` reads `resolved.json` + `http_probe.csv`, generates `domain_ip_pairs.txt`, `all_resolved_ips.txt`, and `phase1/resolution_summary.csv` (domain, ip_count, first_seen, modules).

5. **Quiet Mode Controls**
   - `config/recon.yml` includes `max_threads`, `base_delay`, `jitter`, `passive_only` toggles per module.
   - Orchestrator enforces per-domain sleep windows + optional global rate limit.

6. **Logging & Telemetry**
   - Structured log per module under `logs/phase1/<module>.log` (JSON lines).
   - Central summary log capturing counts, durations, errors for run.sh output.

7. **Deliverables for Phase 1**
   - Refactored `ReconOrchestrator.py`, `resolver.py`, `http_probe.py`, `ip_harvester.py`.
   - Config files: `config/recon.yml`, `config/http_probe.yml`.
   - Updated workflow spec stage entries + tests covering sample target set.

8. **Open Questions**
   - Which legacy modules (amass, stage2_recon) should be supported out-of-box?
   - Are there API quotas (Subfinder, Shodan) that require credential vault integration?

Next action: inventory existing scripts/libs for each enumerator to confirm dependencies and begin refactor stubs.

### Enhancement Opportunities (2025-11-07 00:40:30 UTC)
- **Additional Scripts**: change-detection/diff engine (compare current vs prior runs), passive asset intelligence fetcher (CT logs, builtwith, ASN intel), exposure tagger (map assets to business units/criticality), threat context enricher (CVE/newsfeeds for detected services), compliance mapper (PCI/HIPAA flags).
- **Testing Layers**: add unit tests per module, stage-level integration tests with synthetic targets, regression suite using recorded data, and dry-run mode to validate configs without touching targets.
- **Client Data Gaps**: highlight service banners/versions, geolocation & hosting ownership, historical trends per asset, severity scoring rationale, remediation guidance, related incidents/breaches, credential leak monitoring hooks, and optional dark web/dump feeds.
- **Reporting Upgrades**: include executive summary metrics, MITRE ATT&CK mapping, asset prioritization tables, evidence bundles with hashes, and change log between runs.

Next step: fold these enhancements into phase plans (esp. spec generator + reporting).

### Enhancement Integration Plan (2025-11-07 00:42:06 UTC)
1. **Diff & Change Detection**
   - Script: `run_diff.py` compares `raw_outputs` vs previous run (store baseline in `results/history`).
   - Outputs: `changes_summary.json`, `changes_report.csv` consumed by Report Builder + Reporting Toolkit.
2. **Passive Intelligence Harvesters**
   - Script family: `passive_intel/*.py` (CT logs, BuiltWith/Tech stack, ASN/Geo).
   - Phase placement: after Recon aggregation, before DNS suite; outputs `passive_intel.json`.
3. **Threat Context Enricher**
   - Script: `threat_context.py` maps exposed services to CVEs/MITRE techniques, auto-pulls advisories.
   - Phase placement: Phase 3.5 (post service scan).
4. **Compliance Mapper**
   - Script: `compliance_mapper.py` tags assets (PCI, HIPAA, SOC2) based on domain metadata + service types.
5. **Credential/Dark Web Hooks**
   - Optional module `credential_monitor.py` leveraging safe APIs; outputs alerts to `processed/alerts`.
6. **Testing Harness**
   - Add `tests/unit/` per module + `tests/integration/phaseX/` with fixtures.
   - Provide `run_tests.py` invoked via CI or manually before `run.sh`.
7. **Reporting Enhancements**
   - Expand `report_builder.py` schema to include severity rationale, remediation guidance, ATT&CK mapping, evidence hashes, change log diff results.

Action: incorporate these scripts into the workflow spec outline once stubs exist and update phase plans accordingly.

### Next Action Decision (2025-11-07 00:45:27 UTC)
- Logical starting point: finalize Recon module inventory (Phase 1 deliverable) because every downstream enhancement depends on clean domain/IP artifacts.
- Task: catalog existing enumeration scripts/libraries (SubDomz.sh, assetfinder, subfinder, amass, gau, multitwist) with required binaries/configs, then design module interfaces.
- Parallel prep: initialize git to capture baseline before touching code.

### Version Control Status (2025-11-07 00:47:46 UTC)
- Initialized git repository at project root (`git init`).
- Next steps: create baseline commit once inventory docs updated; adopt branch naming `main` (rename once ready) and feature branches `feature/<area>`.

### Recon Enumerator Inventory (2025-11-07 00:47:59 UTC)
| Module | Artifact | Dependencies | Notes |
| --- | --- | --- | --- |
| SubDomz | SubDomz.sh (bash) | curl, jq, sed, grep | Passive crt.sh/bufferover/web.archive fallback |
| assetfinder | external binary | go install assetfinder (projectdiscovery) | Passively enumerates via APIs (Wayback, crt) |
| subfinder | external binary | Subfinder config (~/.config/subfinder/provider-config.yaml) | API-driven enumeration (Virustotal, SecurityTrails, etc.) |
| amass | external binary | Amass config & API keys (~/.config/amass/config.ini) | Deep passive/active discovery |
| gau | external binary | gau config (~/.gau.toml optional) | Fetches archived URLs; we parse hostnames |
| multitwist/dnstwister | Python scripts | requests, whois, tldextract | Typosquat domain generator |
| stage2_recon / Recon1_old | legacy python | subprocess, os | Useful for reference only |
| http_prober.py | python helper | httpx via requests/csv | Currently writes httpx_output.txt |

### Recon Scaffold Progress (2025-11-07 00:51:28 UTC)
- Created `recon/` package with module registry + base class, plus concrete adapters for SubDomz, assetfinder, subfinder, amass, and gau.
- Added `config/recon.yml` to drive module toggles, rate limits, and defaults; introduced `pyyaml` dependency.
- Implemented `ReconOrchestrator.py` CLI that loads config/targets, executes modules per-domain (threaded), and writes structured outputs (`sources/`, `aggregated_domains.json`, `all_domains.txt`, per-domain recon CSV, phase summary).
- Initialized git repository; baseline commit pending once we finish planning docs.
- Next up: add resolver/http probe/IP harvester scaffolding + target normalizer script to feed orchestrator.

### New Components Added (2025-11-07 00:54:01 UTC)
- `TargetNormalizer.py`: converts `targets.txt` into normalized JSON with optional tags.
- `resolver.py`: quiet DNS resolution pipeline producing `resolved.json`.
- `http_probe.py`: lightweight HTTP prober (structured CSV output, shared logging).
- Extended requirements (added pyyaml, fixed duplicates) and created `recon/modules` scaffolding.

Next: add `ip_harvester.py`, integrate new stage definitions into spec outline, and begin wiring these scripts into run.sh/master_recon.

### Recon Chain Additions (2025-11-07 00:55:21 UTC)
- Added `TargetNormalizer.py`, `resolver.py`, `http_probe.py` (with JSON import fix), and `ip_harvester.py` generating `domain_ip_pairs.txt`, `all_resolved_ips.txt`, and `resolution_summary.csv`.
- These scripts complete the Phase 1 pipeline from raw targets → structured recon outputs → resolved IP artifacts.
- Next focus: wire these into the workflow spec builder and master orchestrator, then create baseline git commit.
