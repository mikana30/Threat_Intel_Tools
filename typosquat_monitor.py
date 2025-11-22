#!/usr/bin/env python3
"""
Typosquat Monitor
-----------------
Generates typosquatted domains via dnstwister API and reports active candidates.
"""

import argparse
import csv
import logging
import time
from pathlib import Path
from typing import List

import requests
import yaml

from dev_mode import get_target_cap, load_env_settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("logs/typosquat_monitor.log", mode="w"), logging.StreamHandler()],
)
logger = logging.getLogger("typosquat")
session = requests.Session()
session.headers.update({"User-Agent": "ThreatIntelTyposquat/1.0"})


def load_config(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def generate_typos(domain: str, timeout: float) -> List[dict]:
    try:
        base_url = f"https://dnstwister.report/api/to_hex/{domain}"
        fuzz_url = session.get(base_url, timeout=timeout).json().get("fuzz_url")
        if not fuzz_url:
            return []
        data = session.get(fuzz_url, timeout=timeout).json()
        return data.get("fuzzy_domains", [])
    except Exception as exc:
        logger.warning("Typosquat lookup failed for %s: %s", domain, exc)
        return []


def is_candidate(entry: dict, cfg: dict) -> bool:
    domain = entry.get("domain", "")
    for keyword in cfg.get("block_keywords", []):
        if keyword in domain:
            return False
    allowed = cfg.get("allow_tlds", [])
    return not allowed or any(domain.endswith(tld) for tld in allowed)


def main():
    parser = argparse.ArgumentParser(description="Typosquat monitoring utility")
    parser.add_argument("--input", required=True, help="Domains file (txt)")
    parser.add_argument("--config", default="config/typosquat.yml")
    parser.add_argument(
        "--env-config",
        default="config/environment.yml",
        help="Optional environment config that may enable dev caps",
    )
    parser.add_argument("--output", required=True, help="CSV output")
    args = parser.parse_args()

    cfg = load_config(Path(args.config))
    timeout = cfg.get("general", {}).get("timeout", 10)
    delay = cfg.get("general", {}).get("delay", 0.5)
    env_settings = load_env_settings(Path(args.env_config))
    cap = get_target_cap(env_settings)

    targets = [line.strip() for line in Path(args.input).read_text().splitlines() if line.strip()]
    if cap:
        original = len(targets)
        targets = targets[:cap]
        logger.info(
            "Dev target cap active (%d) - limiting typosquat scans to first %d of %d domains",
            cap,
            len(targets),
            original,
        )

    rows = []
    for domain in targets:
        logger.info("Processing %s", domain)
        entries = generate_typos(domain, timeout)
        for entry in entries:
            if is_candidate(entry, cfg):
                rows.append(
                    {
                        "root_domain": domain,
                        "typo_domain": entry.get("domain"),
                        "active": entry.get("active"),
                        "dns_a": ",".join(entry.get("dns_a", [])),
                        "dns_ns": ",".join(entry.get("dns_ns", [])),
                        "fuzzer": entry.get("fuzzer"),
                        "score": entry.get("score"),
                    }
                )
        time.sleep(delay)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["root_domain", "typo_domain", "active", "dns_a", "dns_ns", "fuzzer", "score"],
        )
        writer.writeheader()
        writer.writerows(rows)

    logger.info("Collected %d typosquat entries", len(rows))


if __name__ == "__main__":
    main()
