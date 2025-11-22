#!/usr/bin/env python3
"""
DNS format adapter: Convert resolved.json to DnsResolver_out.csv format.

Reads phase1/resolved.json (JSON: {"domain": {"a": [ips], "aaaa": [ips]}})
Outputs DnsResolver_out.csv (CSV: domain,type,target,ip,stale)
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
from pathlib import Path

from tqdm import tqdm

import dev_mode

logger = logging.getLogger(__name__)


def main():
    """Main entry point for DNS format adapter."""
    parser = argparse.ArgumentParser(
        description="Convert resolved.json to DnsResolver_out.csv format"
    )
    parser.add_argument(
        "--resolved-json",
        type=Path,
        required=True,
        help="Path to resolved.json input file",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Path to output CSV file",
    )
    args = parser.parse_args()

    # Load dev mode settings
    env_settings = dev_mode.load_env_settings()
    dev_cap = dev_mode.get_target_cap(env_settings)

    # Read resolved.json
    try:
        with args.resolved_json.open("r", encoding="utf-8") as fh:
            resolved_data = json.load(fh)
    except Exception as exc:
        logger.error("Failed to read %s: %s", args.resolved_json, exc)
        return 1

    # Prepare rows for CSV output
    rows = []
    domains = list(resolved_data.keys())

    # Apply dev cap if active
    if dev_cap:
        logger.info("Dev mode active: limiting to %d domains", dev_cap)
        domains = domains[:dev_cap]

    # Process each domain
    for domain in tqdm(domains, desc="Processing domains"):
        record_data = resolved_data[domain]
        a_records = record_data.get("a", [])

        # Output A records
        for ip in a_records:
            rows.append(
                {
                    "domain": domain,
                    "type": "A",
                    "target": domain,
                    "ip": ip,
                    "stale": "false",
                }
            )

    # Write CSV output
    try:
        with args.output.open("w", newline="", encoding="utf-8") as csvfile:
            fieldnames = ["domain", "type", "target", "ip", "stale"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        logger.info("Wrote %d rows to %s", len(rows), args.output)
    except Exception as exc:
        logger.error("Failed to write %s: %s", args.output, exc)
        return 1

    return 0


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    exit(main())
