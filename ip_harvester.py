#!/usr/bin/env python3
"""
IP Harvester
------------
Aggregates resolved domains and HTTP probe data into consolidated artifacts.
"""

import argparse
import csv
import json
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("logs/ip_harvester.log", mode="w"), logging.StreamHandler()],
)
logger = logging.getLogger("ip_harvester")


def read_http_statuses(path: Path) -> dict[str, list[str]]:
    if not path.exists():
        return {}
    statuses = {}
    with path.open("r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            host = row["url"].split("://", 1)[-1].split("/")[0]
            statuses.setdefault(host, []).append(f"{row['status'] or ''}:{row['server'] or ''}")
    return statuses


def main():
    parser = argparse.ArgumentParser(description="Harvest IPs and summary data")
    parser.add_argument("--resolved-json", required=True, help="Path to resolved.json")
    parser.add_argument("--http-probe", help="Optional http_probe.csv for context")
    parser.add_argument("--pairs-output", required=True, help="Output for domain_ip_pairs.txt")
    parser.add_argument("--ips-output", required=True, help="Output for all_resolved_ips.txt")
    parser.add_argument("--summary-output", required=True, help="Output CSV summarizing resolution")
    args = parser.parse_args()

    resolved = json.loads(Path(args.resolved_json).read_text())
    http_statuses = read_http_statuses(Path(args.http_probe)) if args.http_probe else {}

    unique_ips = set()
    pairs_lines = []
    summary_rows = []
    for domain, data in resolved.items():
        ipv4 = data.get("a", [])
        ipv6 = data.get("aaaa", [])
        for ip in ipv4 + ipv6:
            unique_ips.add(ip)
            pairs_lines.append(f"{domain},{ip}")
        summary_rows.append(
            {
                "domain": domain,
                "ipv4_count": len(ipv4),
                "ipv6_count": len(ipv6),
                "http_observations": ";".join(http_statuses.get(domain, [])),
            }
        )

    Path(args.pairs_output).write_text("\n".join(sorted(pairs_lines)))
    Path(args.ips_output).write_text("\n".join(sorted(unique_ips)))

    summary_path = Path(args.summary_output)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with summary_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["domain", "ipv4_count", "ipv6_count", "http_observations"]
        )
        writer.writeheader()
        writer.writerows(sorted(summary_rows, key=lambda r: r["domain"]))

    logger.info(
        "Harvested %d domains, %d unique IPs", len(summary_rows), len(unique_ips)
    )


if __name__ == "__main__":
    main()
