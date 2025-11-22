import argparse
import concurrent.futures
import csv
import idna
import random
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
import yaml
from requests.adapters import HTTPAdapter
from tqdm import tqdm
from urllib3.util.retry import Retry

from dev_mode import get_target_cap, load_env_settings


def load_config(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"S3 config not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def build_session(cfg: dict) -> requests.Session:
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
        variant = re.sub(r"[^a-z0-9\-]", "-", variant.lower())
        variants.append(variant.strip("-"))
    deduped = list(dict.fromkeys([v for v in variants if v]))
    return deduped[:max_variants] if max_variants else deduped

def resolve_ip(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return "N/A"


def get_bucket_keys(bucket_url: str, ctx: dict) -> list[str]:
    session = ctx["session"]
    max_keys = ctx["max_keys"]
    try:
        resp = session.get(bucket_url, timeout=ctx["timeout"])
        if resp.status_code == 200 and "ListBucketResult" in resp.text:
            return re.findall(r"<Key>(.*?)</Key>", resp.text)[:max_keys]
    except Exception:
        return []
    return []


def check_single_region(bucket_name, region, origin_domain, origin_ip, ctx):
    """Check a single S3 region for bucket existence."""
    session = ctx["session"]
    headers = ctx["headers"]
    timeout = ctx["timeout"]
    base_delay = ctx["base_delay"]
    jitter = ctx["jitter"]
    max_sample_files = ctx.get("max_sample_files", 5)
    verbose = ctx.get("verbose", False)

    url = f"https://{bucket_name}.s3.{region}.amazonaws.com"

    # Rate limiting delay
    if base_delay > 0 or jitter > 0:
        time.sleep(max(0.0, base_delay + random.uniform(0, max(0.0, jitter))))

    try:
        response = session.head(url, headers=headers, timeout=timeout)

        if response.status_code == 200:
            return (origin_domain, origin_ip, bucket_name, region, "Public (200 OK)", "High", "")
        elif response.status_code == 403:
            return (origin_domain, origin_ip, bucket_name, region, "Exists but Private (403 Forbidden)", "Medium", "")

    except requests.RequestException:
        pass

    return None  # Not found in this region


def check_bucket(task: tuple[str, str, str], ctx: dict):
    """Check if S3 bucket exists across multiple regions in parallel."""
    bucket_name, origin_domain, origin_ip = task
    regions = ctx["regions"]

    # Check all regions in parallel
    with ThreadPoolExecutor(max_workers=len(regions)) as executor:
        futures = {
            executor.submit(check_single_region, bucket_name, region, origin_domain, origin_ip, ctx): region
            for region in regions
        }

        for future in as_completed(futures):
            result = future.result()
            if result:  # Found bucket in this region
                return result

    # Not found in any region
    return (origin_domain, origin_ip, bucket_name, "N/A", "Not Found", "None", "")

def clean_domain(domain: str) -> str | None:
    domain = domain.strip().lower()
    domain = re.sub(r"[^a-z0-9\.\-]", "", domain)
    if not domain or "." not in domain:
        return None
    try:
        return idna.encode(domain).decode("ascii")
    except idna.IDNAError:
        return None


def load_domains(filepath: Path) -> list[str]:
    domains: list[str] = []
    with filepath.open("r", encoding="utf-8") as fh:
        for line in fh:
            clean = clean_domain(line)
            if clean:
                domains.append(clean)
    return domains


def main():
    parser = argparse.ArgumentParser(description="S3 bucket exposure scanner")
    parser.add_argument("-i", "--input", required=True, help="Domains file")
    parser.add_argument("-o", "--output", required=True, help="CSV output path")
    parser.add_argument("-t", "--threads", type=int, help="Optional thread override")
    parser.add_argument("--config", default="config/s3.yml", help="Config file")
    parser.add_argument(
        "--env-config",
        default="config/environment.yml",
        help="Optional environment config for dev caps",
    )
    args = parser.parse_args()

    cfg = load_config(Path(args.config))
    general = cfg.get("general", {})
    session = build_session(cfg)
    user_agent = general.get("user_agent", "BucketScanner/2.0")
    ctx = {
        "session": session,
        "regions": general.get(
            "regions", ["us-east-1", "us-west-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
        ),
        "user_agent": user_agent,
        "headers": {"User-Agent": user_agent},
        "timeout": float(general.get("timeout", 6.0)),
        "base_delay": float(general.get("base_delay", 0.2)),
        "jitter": float(general.get("jitter", 0.4)),
        "max_keys": int(general.get("max_keys", 10)),
    }

    domains = load_domains(Path(args.input))
    env_settings = load_env_settings(Path(args.env_config))
    cap = get_target_cap(env_settings)
    if cap:
        domains = domains[:cap]
        logger_msg = f"Dev cap active ({cap}) for S3 scan."
        print(logger_msg)
    max_domains = general.get("max_domains")
    if max_domains:
        domains = domains[: max_domains]

    if not domains:
        print("[!] No domains available for S3 bucket scanning.")
        return

    patterns = general.get("bucket_variants") or [
        "{base}",
        "{root}",
        "{base}-assets",
        "{base}-media",
        "{base}-static",
        "cdn-{base}",
        "img-{base}",
        "files-{base}",
        "{base}-backup",
        "{base}-prod",
        "{base}-dev",
    ]
    max_variants = general.get("max_variants_per_domain")
    bucket_tasks: list[tuple[str, str, str]] = []
    for domain in domains:
        ip = resolve_ip(domain)
        for bucket in generate_bucket_names(domain, patterns, max_variants or 0):
            bucket_tasks.append((bucket, domain, ip))

    if not bucket_tasks:
        print("[!] No bucket permutations generated.")
        return

    threads = args.threads or general.get("max_threads", 10)
    print(f"[*] Checking {len(bucket_tasks)} bucket variants across {len(domains)} domains using {threads} threads.")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {executor.submit(check_bucket, task, ctx): task for task in bucket_tasks}
        for future in tqdm(
            concurrent.futures.as_completed(future_map),
            total=len(future_map),
            desc="Scanning",
            ncols=80,
        ):
            try:
                results.append(future.result())
            except Exception as exc:
                bucket, domain, _ = future_map[future]
                results.append((domain, "N/A", bucket, "N/A", "Error", str(exc), ""))

    with open(args.output, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            ["origin_domain", "resolved_ip", "bucket_name", "region", "status", "risk", "example_keys"]
        )
        for row in results:
            writer.writerow(row)

    print(f"[✓] S3 scan complete. Results saved to: {args.output}")


if __name__ == "__main__":
    main()
