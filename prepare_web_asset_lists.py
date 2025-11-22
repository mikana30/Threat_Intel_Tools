#!/usr/bin/env python3
"""
prepare_web_asset_lists.py
--------------------------
Generates supporting text inventories for downstream web exposure checks:
  * live_web_hosts_domains.txt  – hostnames stripped of scheme/paths
  * domain_ip_pairs.txt         – "domain ip" pairs from Recon_out.csv

These lightweight artifacts let the workflow reuse existing recon outputs
without re-processing them in multiple scripts.
"""

import argparse
import csv
import sys
from pathlib import Path
from urllib.parse import urlparse


def load_live_hosts(path: Path) -> list[str]:
    try:
        lines = path.read_text().splitlines()
    except FileNotFoundError:
        raise FileNotFoundError(f"Live web hosts file not found: {path}") from None

    hosts: list[str] = []
    seen: set[str] = set()
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        parsed = urlparse(line if "://" in line else f"https://{line}")
        hostname = parsed.netloc.lower()
        if hostname and hostname not in seen:
            seen.add(hostname)
            hosts.append(hostname)
    return hosts


def build_domain_ip_pairs(path: Path) -> list[str]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            rows = list(reader)
    except FileNotFoundError:
        raise FileNotFoundError(f"Recon CSV not found: {path}") from None
    except Exception as exc:
        raise RuntimeError(f"Failed to parse {path}: {exc}") from exc

    pairs: list[str] = []
    seen: set[tuple[str, str]] = set()

    for row in rows:
        domain = (row.get("domain") or "").strip().lower()
        ip = (row.get("ip") or "").strip()
        if not domain or not ip:
            continue
        key = (domain, ip)
        if key in seen:
            continue
        seen.add(key)
        pairs.append(f"{domain} {ip}")
    return pairs


def main():
    parser = argparse.ArgumentParser(description="Generate helper inventories from recon outputs.")
    parser.add_argument("--recon-csv", required=True, help="Path to Recon_out.csv.")
    parser.add_argument("--live-hosts", required=True, help="Path to live_web_hosts.txt.")
    parser.add_argument("--output-dir", required=True, help="Directory to write helper files into.")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        hosts = load_live_hosts(Path(args.live_hosts))
        pairs = build_domain_ip_pairs(Path(args.recon_csv))
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)

    hosts_path = output_dir / "live_web_hosts_domains.txt"
    pairs_path = output_dir / "domain_ip_pairs.txt"

    hosts_path.write_text("\n".join(hosts))
    pairs_path.write_text("\n".join(pairs))

    print(f"[OK] Wrote {len(hosts)} hosts to {hosts_path}")
    print(f"[OK] Wrote {len(pairs)} domain/ip pairs to {pairs_path}")


if __name__ == "__main__":
    main()
