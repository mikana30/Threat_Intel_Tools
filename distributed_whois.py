#!/usr/bin/env python3
"""
distributed_whois.py
--------------------
Stateful WHOIS runner that processes small batches of IPs per stage so we can
spread lookups across the workflow and avoid rate limits.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import logging
import math
import random
import subprocess
import time
from pathlib import Path
from typing import Iterable, List

import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("logs/distributed_whois.log", mode="a"), logging.StreamHandler()],
)
logger = logging.getLogger("distributed_whois")


def load_config(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"WHOIS config not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_ips(path: Path) -> List[str]:
    if not path.exists():
        logger.info("Input IP list %s not found; skipping WHOIS stage.", path)
        return []
    seen = {}
    for line in path.read_text().splitlines():
        value = line.strip()
        if not value:
            continue
        if value not in seen:
            seen[value] = None
    return list(seen.keys())


def load_state(path: Path) -> dict:
    if not path.exists():
        return {"processed_ips": []}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        logger.warning("State file %s is corrupted; starting fresh.", path)
        return {"processed_ips": []}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2))


def ensure_output(output_path: Path) -> None:
    if output_path.exists():
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ip", "whois_info"])


def run_command(cmd: List[str], timeout: int) -> str | None:
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if completed.returncode != 0:
            logger.warning("WHOIS command failed (%s): %s", completed.returncode, completed.stderr.strip())
            return completed.stdout or ""
        return completed.stdout
    except subprocess.TimeoutExpired:
        logger.warning("WHOIS command timed out for %s", cmd[-1])
        return None
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Unexpected WHOIS error for %s: %s", cmd[-1], exc)
        return None


def extract_relevant(raw: str | None, keywords: Iterable[str]) -> str:
    if not raw:
        return "Error: WHOIS lookup failed or returned empty."
    lower_keywords = [kw.lower() for kw in keywords]
    hits = []
    for line in raw.splitlines():
        normalized = line.strip()
        if not normalized:
            continue
        lower_line = normalized.lower()
        if any(kw in lower_line for kw in lower_keywords):
            hits.append(normalized)
    if not hits:
        return "No relevant info found."
    return "; ".join(hits)


def main():
    parser = argparse.ArgumentParser(description="Distributed WHOIS batch processor")
    parser.add_argument("-i", "--input-file", required=True, type=Path, help="all_resolved_ips.txt")
    parser.add_argument("-o", "--output-file", required=True, type=Path, help="whois_results.csv (append)")
    parser.add_argument("--state-file", required=True, type=Path, help="JSON file to track processed IPs")
    parser.add_argument("--batch-size", type=int, help="Optional override for batch size")
    parser.add_argument("--config", default="config/whois.yml", help="WHOIS config file")
    args = parser.parse_args()

    cfg = load_config(Path(args.config))
    general = cfg.get("general", {})
    base_delay = float(general.get("base_delay", 1.5))
    jitter = float(general.get("jitter", 1.0))
    retries = int(general.get("retries", 0))
    command = general.get("command", "whois")
    timeout = int(general.get("timeout", 30))
    keywords = general.get("keywords") or []

    all_ips = load_ips(Path(args.input_file))
    if not all_ips:
        return

    # Dynamic batch sizing: calculate based on total IPs and number of batches
    total_ips = len(all_ips)
    num_batches = int(general.get("num_batches", 6))
    calculated_batch_size = math.ceil(total_ips / num_batches)

    # Allow CLI override, otherwise use calculated size, fallback to old default
    batch_size = args.batch_size or calculated_batch_size or int(general.get("batch_size", 25))

    logger.info(
        "Dynamic batch sizing: %d total IPs / %d batches = %d IPs per batch",
        total_ips, num_batches, batch_size
    )

    state = load_state(Path(args.state_file))
    processed = set(state.get("processed_ips", []))
    unprocessed = [ip for ip in all_ips if ip not in processed]
    if not unprocessed:
        logger.info("All %d IPs have WHOIS coverage already; skipping.", len(all_ips))
        return

    valid_unprocessed = []
    for ip in unprocessed:
        try:
            ipaddress.ip_address(ip)
            valid_unprocessed.append(ip)
        except ValueError:
            logger.warning("Skipping non-IP entry in WHOIS list: %s", ip)

    if not valid_unprocessed:
        logger.info("No valid IPs remain for WHOIS.")
        return

    batch = valid_unprocessed[:batch_size]
    logger.info("Processing WHOIS batch of %d (remaining %d/%d).", len(batch), len(unprocessed) - len(batch), len(all_ips))
    ensure_output(Path(args.output_file))

    with Path(args.output_file).open("a", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        for ip in batch:
            logger.info("WHOIS lookup for %s", ip)
            result = None
            attempts = 0
            while attempts <= retries:
                attempts += 1
                output = run_command([command, ip], timeout)
                result = extract_relevant(output, keywords)
                if output or attempts > retries:
                    break
                logger.info("Retrying WHOIS for %s (%d/%d)", ip, attempts, retries)
                time.sleep(base_delay)
            writer.writerow([ip, result])
            processed.add(ip)
            delay = base_delay + random.uniform(0, max(0, jitter))
            time.sleep(max(0, delay))

    save_state(
        Path(args.state_file),
        {
            "processed_ips": sorted(processed),
            "last_run": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "last_batch_size": len(batch),
        },
    )
    logger.info("WHOIS batch complete. Total processed: %d / %d.", len(processed), len(all_ips))


if __name__ == "__main__":
    main()
