#!/usr/bin/env python3
"""
Resolver Pipeline
-----------------
Consumes recon aggregated JSON and performs DNS resolution with throttling.
"""
from __future__ import annotations

import argparse
import json
import logging
import random
import time
from pathlib import Path

import dns.resolver

from dev_mode import get_target_cap, load_env_settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("logs/resolver.log", mode="w"), logging.StreamHandler()],
)
logger = logging.getLogger("resolver")


def resolve_domain(domain: str, resolver: dns.resolver.Resolver) -> dict:
    records = {"a": [], "aaaa": []}
    for record_type in ("A", "AAAA"):
        try:
            answers = resolver.resolve(domain, record_type, lifetime=5)
            records[record_type.lower()] = sorted({str(ans) for ans in answers})
        except Exception:
            # suppress noisy NXDOMAIN/logs; this is expected for many hosts
            continue
    return records


def main():
    parser = argparse.ArgumentParser(description="Resolve domains to IPs")
    parser.add_argument("--input-dir", required=True, help="Path to recon_outputs directory")
    parser.add_argument("--output", required=True, help="Path for resolved.json")
    parser.add_argument("--base-delay", type=float, default=0.2, help="Base delay between queries")
    parser.add_argument("--jitter", type=float, default=0.3, help="Random jitter added to delay")
    parser.add_argument(
        "--env-config",
        default="config/environment.yml",
        help="Optional environment config to enforce dev caps",
    )
    args = parser.parse_args()

    base_path = Path(args.input_dir)
    domains = set()
    for agg_path in base_path.glob("*/aggregated_domains.json"):
        data = json.loads(agg_path.read_text())
        for entry in data:
            domains.add(entry["domain"])

    domains = sorted(domains)
    env_settings = load_env_settings(Path(args.env_config))
    cap = get_target_cap(env_settings)
    if cap:
        domains = domains[:cap]
        logger.info("Dev cap active (%d) in resolver - limiting domain list.", cap)

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    resolved_map = {}
    for host in domains:
        records = resolve_domain(host, resolver)
        if records["a"] or records["aaaa"]:
            resolved_map[host] = records
        delay = args.base_delay + random.uniform(0, args.jitter)
        time.sleep(max(0, delay))
    Path(args.output).write_text(json.dumps(resolved_map, indent=2))
    logger.info("Resolved %d hosts -> %d entries", len(domains), len(resolved_map))


if __name__ == "__main__":
    main()
