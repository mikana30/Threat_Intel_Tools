# cloud_bucket_scanner.py
import requests
import csv
import re
import random
import time
import idna
import yaml
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from argparse import ArgumentParser
from tqdm import tqdm
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Import dev_mode utilities
try:
    from dev_mode import get_target_cap, load_env_settings
    DEV_MODE_AVAILABLE = True
except ImportError:
    DEV_MODE_AVAILABLE = False

    def load_env_settings(path):
        return {}

    def get_target_cap(settings):
        return None

def load_config(config_path: Path) -> dict:
    """Load cloud storage configuration from YAML file."""
    if not config_path.exists():
        raise FileNotFoundError(f"Cloud storage config not found: {config_path}")
    with config_path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def build_session(cfg: dict) -> requests.Session:
    """Build requests session with retry logic."""
    retries_cfg = cfg.get("retries", {})
    retry = Retry(
        total=retries_cfg.get("total", 3),
        backoff_factor=retries_cfg.get("backoff_factor", 0.5),
        status_forcelist=retries_cfg.get("status_forcelist", [429, 500, 502, 503, 504]),
        allowed_methods=retries_cfg.get("allowed_methods", ["HEAD", "GET"]),
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def generate_bucket_names(domain: str, patterns: list[str], max_variants: int) -> list[str]:
    """Generate bucket name variants from domain."""
    base = domain.replace(".", "-")
    root = domain.split(".")[0]
    context = {
        "base": base,
        "root": root,
    }
    variants = []
    for pattern in patterns:
        try:
            variant = pattern.format(**context)
        except KeyError:
            variant = pattern
        # Sanitize bucket name
        variant = re.sub(r"[^a-z0-9\-]", "-", variant.lower())
        variants.append(variant.strip("-"))

    # Deduplicate and limit
    deduped = list(dict.fromkeys([v for v in variants if v]))
    return deduped[:max_variants] if max_variants else deduped


def clean_domain(domain: str) -> str | None:
    """Clean and normalize domain name."""
    domain = domain.strip().lower()
    domain = re.sub(r"[^a-z0-9\.\-]", "", domain)
    if not domain or "." not in domain:
        return None
    try:
        return idna.encode(domain).decode("ascii")
    except idna.IDNAError:
        return None


def fetch_bucket(url, provider, session, timeout, max_sample_files=5, verbose=False):
    """Check if a bucket exists and is accessible."""
    try:
        for scheme in ["https://", "http://"]:
            test_url = url.replace("https://", scheme)
            resp = session.get(test_url, timeout=timeout)
            if resp.status_code in [200, 403]:
                # Determine risk
                if resp.status_code == 200 and ("<Key>" in resp.text or "<Contents>" in resp.text):
                    files = re.findall(r"<Key>(.*?)</Key>", resp.text)
                    sample_files = ", ".join(files[:max_sample_files]) if files else "No files listed"
                    risk = "High"
                    status = "Public"
                elif resp.status_code == 200:
                    sample_files = "No files listed"
                    risk = "Medium"
                    status = "Public (Empty)"
                elif resp.status_code == 403:
                    sample_files = "N/A"
                    risk = "Low"
                    status = "Private"
                else:
                    continue

                if verbose:
                    print(f"[{provider}] {test_url} - {status} ({risk}) - {sample_files}")

                return (provider, status, risk, sample_files, test_url)
        return None
    except requests.RequestException:
        return None

def build_cloud_patterns(providers_config: dict) -> dict:
    """Build cloud patterns from provider configuration."""
    patterns = {}

    for provider_name, provider_cfg in providers_config.items():
        if not provider_cfg.get("enabled", True):
            continue

        provider_label = provider_name.replace("_", " ").title()
        provider_patterns = []

        # Handle region-based providers
        regions = provider_cfg.get("regions", [])
        pattern_templates = provider_cfg.get("patterns", [])

        if regions:
            # Expand patterns with regions
            for template in pattern_templates:
                for region in regions:
                    pattern = template.replace("{region}", region)
                    provider_patterns.append(pattern)
        else:
            # No regions, use patterns as-is
            provider_patterns = pattern_templates

        if provider_patterns:
            patterns[provider_label] = provider_patterns

    return patterns


def check_single_provider(bucket_name, provider, pattern, ctx):
    """Check a single cloud provider pattern for bucket existence."""
    session = ctx["session"]
    timeout = ctx["timeout"]
    base_delay = ctx["base_delay"]
    jitter = ctx["jitter"]
    max_sample_files = ctx.get("max_sample_files", 5)
    verbose = ctx.get("verbose", False)

    url = pattern.format(bucket=bucket_name)

    # Rate limiting delay
    if base_delay > 0 or jitter > 0:
        time.sleep(max(0.0, base_delay + random.uniform(0, max(0.0, jitter))))

    res = fetch_bucket(url, provider, session, timeout, max_sample_files, verbose)

    if res:
        # res format: (provider, status, risk, sample_files, test_url)
        return (bucket_name, res[0], res[1], res[2], res[3], res[4])

    return None  # Not found with this provider


def check_bucket(bucket_name, cloud_patterns, ctx):
    """Check a single bucket name across all cloud providers in parallel."""
    # Flatten all provider patterns into a list
    provider_checks = [
        (provider, pattern)
        for provider, patterns in cloud_patterns.items()
        for pattern in patterns
    ]

    # Check all providers in parallel
    results = []
    with ThreadPoolExecutor(max_workers=len(provider_checks)) as executor:
        futures = {
            executor.submit(
                check_single_provider, bucket_name, provider, pattern, ctx
            ): (provider, pattern)
            for provider, pattern in provider_checks
        }

        for future in as_completed(futures):
            result = future.result()
            if result:  # Found bucket with this provider
                results.append(result)

    return results

def load_domains(filepath: Path) -> list[str]:
    """Load and clean domains from input file."""
    domains = []
    with filepath.open("r", encoding="utf-8") as fh:
        for line in fh:
            clean = clean_domain(line)
            if clean:
                domains.append(clean)
    return domains


def main():
    parser = ArgumentParser(description="Multi-cloud storage bucket scanner")
    parser.add_argument("-i", "--input", required=True, help="Input file of domains")
    parser.add_argument("-o", "--output", required=True, help="Output CSV path")
    parser.add_argument("-t", "--threads", type=int, help="Optional thread override")
    parser.add_argument("--config", default="config/cloud_storage.yml", help="Cloud storage config file")
    parser.add_argument(
        "--env-config",
        default="config/environment.yml",
        help="Environment config for dev caps",
    )
    parser.add_argument("--verbose", action="store_true", help="Show verbose output while scanning")
    args = parser.parse_args()

    # Load configuration
    cfg = load_config(Path(args.config))
    general = cfg.get("general", {})
    providers_config = cfg.get("providers", {})

    # Build session with retry logic
    session = build_session(cfg)

    # Build cloud patterns from enabled providers
    cloud_patterns = build_cloud_patterns(providers_config)

    if not cloud_patterns:
        print("[!] No cloud providers enabled in configuration.")
        return

    # Create context for scanning
    ctx = {
        "session": session,
        "timeout": float(general.get("timeout", 5.0)),
        "base_delay": float(general.get("base_delay", 0.15)),
        "jitter": float(general.get("jitter", 0.3)),
        "max_sample_files": int(general.get("max_sample_files", 5)),
        "verbose": args.verbose or general.get("verbose", False),
    }

    # Load domains
    domains = load_domains(Path(args.input))

    # Apply dev mode caps if available
    if DEV_MODE_AVAILABLE:
        env_settings = load_env_settings(Path(args.env_config))
        cap = get_target_cap(env_settings)
        if cap:
            domains = domains[:cap]
            print(f"[*] Dev cap active ({cap}) for cloud storage scan.")

    # Apply config max_domains
    max_domains = general.get("max_domains")
    if max_domains:
        domains = domains[:max_domains]

    if not domains:
        print("[!] No domains available for cloud storage scanning.")
        return

    # Generate bucket name variants
    bucket_patterns = general.get("bucket_variants") or [
        "{base}",
        "{root}",
        "{base}-assets",
        "{base}-media",
        "{base}-static",
        "cdn-{base}",
        "files-{base}",
    ]
    max_variants = general.get("max_variants_per_domain", 15)

    bucket_names = []
    for domain in domains:
        variants = generate_bucket_names(domain, bucket_patterns, max_variants)
        bucket_names.extend(variants)

    # Deduplicate bucket names
    bucket_names = list(dict.fromkeys(bucket_names))

    if not bucket_names:
        print("[!] No bucket names generated.")
        return

    threads = args.threads or general.get("max_threads", 15)
    print(f"[*] Scanning {len(bucket_names)} bucket variants across {len(cloud_patterns)} cloud providers")
    print(f"[*] Providers: {', '.join(cloud_patterns.keys())}")
    print(f"[*] Using {threads} threads")

    # Scan buckets
    findings = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_bucket, b, cloud_patterns, ctx): b for b in bucket_names}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Scanning", ncols=80):
            try:
                result = future.result()
                if result:
                    findings.extend(result)
            except Exception as exc:
                bucket = futures[future]
                print(f"[!] Error scanning {bucket}: {exc}")

    # Write results
    with open(args.output, 'w', newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["bucket_name", "provider", "status", "risk", "sample_files", "url"])
        writer.writerows(findings)

    print(f"[✓] Cloud storage scan complete. Results saved to: {args.output}")
    print(f"[✓] Total findings: {len(findings)}")


if __name__ == "__main__":
    main()
