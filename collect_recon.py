#!/usr/bin/env python3
"""
collect_recon.py
----------------
Stitches together the structured Phase 1 recon outputs into the legacy-friendly
`Recon_out.csv` + `domains_only.txt` artifacts expected by downstream scripts.

Inputs:
  * recon_outputs/*/aggregated_domains.json -> source attribution
  * phase1/resolved.json                    -> IP mappings
  * phase1/http_probe.csv                   -> HTTP status/server signals

Outputs:
  * Recon_out.csv (domain, ip, http_status, http_title, source_file, sources)
  * domains_only.txt (unique domain list)
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("logs/collect_recon.log", mode="w"), logging.StreamHandler()],
)
logger = logging.getLogger("collect_recon")


def load_inventory(recon_dir: Path) -> dict:
    """
    Load aggregated recon data for each discovered domain.
    """
    inventory: Dict[str, dict] = {}
    for agg_path in recon_dir.glob("*/aggregated_domains.json"):
        root = agg_path.parent.name
        try:
            entries = json.loads(agg_path.read_text())
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse %s: %s", agg_path, exc)
            continue
        for entry in entries or []:
            domain = (entry or {}).get("domain", "").strip().lower()
            if not domain:
                continue
            details = inventory.setdefault(
                domain,
                {
                    "sources": set(),
                    "source_file": str(agg_path.parent / f"{root}_recon.csv"),
                },
            )
            for src in entry.get("sources", []):
                if src:
                    details["sources"].add(src)
    return inventory


def load_resolved(resolved_path: Path) -> dict:
    if not resolved_path.exists():
        logger.warning("Resolved JSON not found: %s", resolved_path)
        return {}
    try:
        return json.loads(resolved_path.read_text())
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse resolved JSON %s: %s", resolved_path, exc)
        return {}


def load_http_observations(http_csv: Path) -> dict:
    if not http_csv.exists():
        logger.warning("HTTP probe CSV not found: %s", http_csv)
        return {}
    observations: Dict[str, List[dict]] = {}
    with http_csv.open("r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            url = (row.get("url") or "").strip()
            if not url:
                continue
            host = url.split("://", 1)[-1].split("/")[0].lower()
            observations.setdefault(host, []).append(
                {
                    "status": row.get("status"),
                    "server": row.get("server") or "",
                    "url": url,
                }
            )
    return observations


def choose_http_signal(entries: Iterable[dict] | None) -> Tuple[str, str]:
    if not entries:
        return "", ""

    best_item = None
    best_score = (-1, 0)
    for idx, item in enumerate(entries):
        status_str = item.get("status")
        try:
            status = int(status_str)
        except (TypeError, ValueError):
            status = 0

        if status == 200:
            tier = 3
        elif 100 <= status < 400:
            tier = 2
        elif status > 0:
            tier = 1
        else:
            tier = 0

        score = (tier, -idx)
        if score > best_score:
            best_score = score
            best_item = item

    if not best_item:
        return "", ""

    status = best_item.get("status") or ""
    server = best_item.get("server") or ""
    return str(status), server


def build_rows(inventory: dict, resolved: dict, http_obs: dict) -> List[dict]:
    all_domains = sorted(set(inventory.keys()) | set(resolved.keys()) | set(http_obs.keys()))
    rows = []
    for domain in all_domains:
        sources = inventory.get(domain, {}).get("sources", set())
        source_file = inventory.get(domain, {}).get("source_file", "")
        ip_entries = resolved.get(domain, {})
        ips = sorted(set(ip_entries.get("a", []) + ip_entries.get("aaaa", [])))
        status, server = choose_http_signal(http_obs.get(domain))
        http_title = server  # reuse column for legacy consumers

        if ips:
            for ip in ips:
                rows.append(
                    {
                        "domain": domain,
                        "ip": ip,
                        "http_status": status,
                        "http_title": http_title,
                        "source_file": source_file,
                        "sources": ";".join(sorted(sources)),
                    }
                )
        else:
            rows.append(
                {
                    "domain": domain,
                    "ip": "",
                    "http_status": status,
                    "http_title": http_title,
                    "source_file": source_file,
                    "sources": ";".join(sorted(sources)),
                }
            )
    return rows


def write_csv(rows: List[dict], output_path: Path) -> None:
    if not rows:
        logger.warning("No recon rows generated; output will be empty.")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["domain", "ip", "http_status", "http_title", "source_file", "sources"]
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    logger.info("Wrote %d rows to %s", len(rows), output_path)


def write_domains_only(rows: List[dict], output_path: Path) -> None:
    domains = sorted({row["domain"] for row in rows if row.get("domain")})
    output_path.write_text("\n".join(domains))
    logger.info("Wrote %d unique domains to %s", len(domains), output_path)


def main():
    parser = argparse.ArgumentParser(description="Collect Phase 1 recon outputs")
    parser.add_argument("--recon-dir", required=True, help="Path to raw_outputs/recon_outputs")
    parser.add_argument("--resolved-json", required=True, help="phase1/resolved.json path")
    parser.add_argument("--http-probe", required=True, help="phase1/http_probe.csv path")
    parser.add_argument("--output-csv", required=True, help="Destination for Recon_out.csv")
    parser.add_argument("--domains-output", required=True, help="Destination for domains_only.txt")
    args = parser.parse_args()

    recon_dir = Path(args.recon_dir)
    inventory = load_inventory(recon_dir)
    resolved = load_resolved(Path(args.resolved_json))
    http_obs = load_http_observations(Path(args.http_probe))

    rows = build_rows(inventory, resolved, http_obs)
    write_csv(rows, Path(args.output_csv))
    write_domains_only(rows, Path(args.domains_output))


if __name__ == "__main__":
    main()
