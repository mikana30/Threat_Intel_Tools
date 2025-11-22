#!/usr/bin/env python3
"""
DNS Suite
---------
Consolidated DNS analysis pipeline.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List

import dns.resolver
import ipaddress
import yaml

from dev_mode import get_target_cap, load_env_settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("logs/dns_suite.log", mode="w"), logging.StreamHandler()],
)
logger = logging.getLogger("dns_suite")


def load_domains(path: Path) -> List[str]:
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def load_config(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def resolve_records(domain: str, resolver: dns.resolver.Resolver) -> Dict[str, List[str]]:
    records = {}
    for record_type in ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]:
        try:
            answers = resolver.resolve(domain, record_type, lifetime=3)
            entries = [answer.to_text().strip('"') for answer in answers]
            if entries:
                records[record_type] = entries
        except Exception:
            continue
    return records


def check_dnssec(domain: str, resolver: dns.resolver.Resolver) -> bool:
    try:
        resolver.resolve(domain, "DNSKEY", lifetime=3)
        return True
    except Exception:
        return False


def check_txt(domain: str, name: str, resolver: dns.resolver.Resolver) -> str:
    try:
        answers = resolver.resolve(name, "TXT", lifetime=3)
        return ";".join(answer.to_text().strip('"') for answer in answers)
    except Exception:
        return ""


def check_spf(domain: str, resolver: dns.resolver.Resolver) -> str:
    return check_txt(domain, domain, resolver)


def check_dmarc(domain: str, resolver: dns.resolver.Resolver) -> str:
    return check_txt(domain, f"_dmarc.{domain}", resolver)


def check_dkim(domain: str, resolver: dns.resolver.Resolver) -> Dict[str, str]:
    selectors = ["default", "selector1", "google"]
    findings = {}
    for sel in selectors:
        name = f"{sel}._domainkey.{domain}"
        value = check_txt(domain, name, resolver)
        if value:
            findings[sel] = value
    return findings


def is_internal(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False


def detect_internal(records: Dict[str, List[str]], resolver: dns.resolver.Resolver) -> List[str]:
    findings = []
    for rtype, values in records.items():
        for val in values:
            if rtype in {"A", "AAAA"} and is_internal(val):
                findings.append(f"{rtype}:{val}")
            elif rtype in {"MX", "CNAME"}:
                host = val.rstrip(".")
                try:
                    answers = resolver.resolve(host, "A", lifetime=3)
                    for ans in answers:
                        addr = ans.address
                        if is_internal(addr):
                            findings.append(f"{rtype}:{host}->{addr}")
                except Exception:
                    continue
    return findings


def is_stale(records: Dict[str, List[str]]) -> bool:
    # Placeholder: mark stale if we have NS but no A/AAAA
    has_ns = bool(records.get("NS"))
    has_address = bool(records.get("A") or records.get("AAAA"))
    return has_ns and not has_address


def process_domain(domain: str, resolver: dns.resolver.Resolver, cfg: dict) -> dict:
    data = {"domain": domain}
    records = resolve_records(domain, resolver)
    data["records"] = records
    if cfg["checks"].get("dnssec"):
        data["dnssec"] = check_dnssec(domain, resolver)
    if cfg["checks"].get("spf"):
        data["spf"] = check_spf(domain, resolver)
    if cfg["checks"].get("dkim"):
        data["dkim"] = check_dkim(domain, resolver)
    if cfg["checks"].get("dmarc"):
        data["dmarc"] = check_dmarc(domain, resolver)
    if cfg["checks"].get("internal_exposure"):
        data["internal_hits"] = detect_internal(records, resolver)
    data["stale"] = is_stale(records)
    return data


def main():
    parser = argparse.ArgumentParser(description="DNS suite runner")
    parser.add_argument("--domains", required=True, help="Input domains file (txt)")
    parser.add_argument("--config", default="config/dns.yml")
    parser.add_argument("--records-csv", required=True)
    parser.add_argument("--health-json", required=True)
    parser.add_argument("--internal-output", required=True)
    parser.add_argument(
        "--env-config",
        default="config/environment.yml",
        help="Optional environment config to honor dev caps",
    )
    args = parser.parse_args()

    domains = load_domains(Path(args.domains))
    env_settings = load_env_settings(Path(args.env_config))
    cap = get_target_cap(env_settings)
    if cap:
        domains = domains[:cap]
        logger.info("Dev cap active (%d) in dns_suite - limiting domain list.", cap)
    if not domains:
        logger.warning("No domains supplied to dns_suite; exiting.")
        return

    cfg = load_config(Path(args.config))
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    max_workers = cfg["general"].get("max_workers", 10)
    base_delay = cfg["general"].get("base_delay", 0.1)
    jitter = cfg["general"].get("jitter", 0.2)

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_domain, d, resolver, cfg): d for d in domains}
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as exc:
                logger.warning("Failed domain %s: %s", futures[future], exc)
            time.sleep(max(0.0, base_delay + random.uniform(0, jitter)))

    # Write CSV
    records_csv = Path(args.records_csv)
    records_csv.parent.mkdir(parents=True, exist_ok=True)
    with records_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["domain", "records", "dnssec", "spf", "dkim", "dmarc", "stale"])
        writer.writeheader()
        for row in results:
            writer.writerow(
                {
                    "domain": row["domain"],
                    "records": json.dumps(row.get("records", {})),
                    "dnssec": row.get("dnssec", False),
                    "spf": row.get("spf", ""),
                    "dkim": json.dumps(row.get("dkim", {})),
                    "dmarc": row.get("dmarc", ""),
                    "stale": row.get("stale", False),
                }
            )

    # Health JSON
    Path(args.health_json).write_text(json.dumps(results, indent=2))

    internal_rows = []
    for item in results:
        for hit in item.get("internal_hits", []):
            internal_rows.append({"domain": item["domain"], "finding": hit})
    internal_path = Path(args.internal_output)
    internal_path.parent.mkdir(parents=True, exist_ok=True)
    with internal_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["domain", "finding"])
        writer.writeheader()
        writer.writerows(internal_rows)


if __name__ == "__main__":
    main()
