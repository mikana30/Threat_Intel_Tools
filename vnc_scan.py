#!/usr/bin/env python3
"""
vnc_scan.py
-----------
Stateful, distributed VNC exposure scanner that dials a limited number of
host/port pairs per run so we can spread traffic across the workflow stages.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import math
import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import yaml

from dev_mode import get_target_cap, load_env_settings
from utils.atomic_write import atomic_write_json

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("logs/vnc_scan.log", mode="a"), logging.StreamHandler()],
)
logger = logging.getLogger("vnc_scan")


def load_hosts(path: Path) -> List[Tuple[str, str]]:
    if not path.exists():
        logger.warning("Hosts file %s not found; skipping VNC scan.", path)
        return []

    hosts: Dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        if "," in line:
            domain, ip = [item.strip() for item in line.split(",", 1)]
        else:
            parts = line.split()
            if len(parts) == 1:
                domain, ip = parts[0], parts[0]
            else:
                domain, ip = parts[0], parts[1]
        if not ip:
            continue
        hosts.setdefault(ip, domain)
    return [(domain, ip) for ip, domain in hosts.items()]


def load_config(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"VNC config not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_state(path: Path) -> dict:
    if not path.exists():
        return {"hosts": {}}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        logger.warning("VNC state file %s is corrupted; starting fresh.", path)
        return {"hosts": {}}


def save_state(path: Path, state: dict) -> None:
    atomic_write_json(path, state)


def ensure_output(path: Path) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["domain", "ip", "port", "status", "banner"])


def next_batch(
    hosts: List[Tuple[str, str]],
    ports: List[int],
    state_hosts: Dict[str, int],
    batch_size: int,
) -> Tuple[List[Tuple[str, str, int]], Dict[str, int]]:
    combos: List[Tuple[str, str, int]] = []
    progress: Dict[str, int] = {}

    for domain, ip in hosts:
        start_idx = min(state_hosts.get(ip, 0), len(ports))
        if start_idx >= len(ports):
            continue
        remaining_ports = ports[start_idx:]
        for port in remaining_ports:
            combos.append((domain, ip, port))
            progress[ip] = progress.get(ip, 0) + 1
            if len(combos) >= batch_size:
                break
        if len(combos) >= batch_size:
            break

    return combos, progress


def scan_port(ip: str, port: int, timeout: float, base_delay: float, jitter: float) -> str | None:
    time.sleep(max(0.0, base_delay + random.uniform(0, max(0.0, jitter))))
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(12)
            if banner.startswith(b"RFB"):
                return banner.decode(errors="ignore")
    except Exception:
        return None
    return None


def main():
    parser = argparse.ArgumentParser(description="Distributed VNC scanner")
    parser.add_argument("--hosts-file", required=True, help="domain_ip_pairs.txt or IP list")
    parser.add_argument("--output", required=True, help="CSV output (append)")
    parser.add_argument("--state-file", required=True, help="State file path")
    parser.add_argument("--config", default="config/vnc.yml", help="VNC config YAML")
    parser.add_argument(
        "--env-config",
        default="config/environment.yml",
        help="Optional environment config for dev caps",
    )
    args = parser.parse_args()

    cfg = load_config(Path(args.config))
    general = cfg.get("general", {})
    ports = general.get("ports") or []
    if not ports:
        logger.error("No VNC ports configured; aborting.")
        return

    max_threads = int(general.get("max_threads", 5))
    timeout = float(general.get("connect_timeout", 3.0))
    base_delay = float(general.get("base_delay", 0.5))
    jitter = float(general.get("jitter", 0.5))

    hosts = load_hosts(Path(args.hosts_file))
    if not hosts:
        logger.info("No hosts available for VNC scanning.")
        return

    env_settings = load_env_settings(Path(args.env_config))
    cap = get_target_cap(env_settings)
    if cap:
        hosts = hosts[:cap]
        logger.info("Dev cap active (%d) for VNC scan.", cap)

    # Dynamic batch sizing: calculate based on total host/port combinations
    total_hosts = len(hosts)
    num_ports = len(ports)
    total_combos = total_hosts * num_ports
    num_batches = int(general.get("num_batches", 3))
    calculated_batch_size = math.ceil(total_combos / num_batches)

    # Use calculated size, fallback to old default
    batch_size = calculated_batch_size or int(general.get("batch_size", 40))

    logger.info(
        "Dynamic batch sizing: %d hosts × %d ports = %d combos / %d batches = %d combos per batch",
        total_hosts, num_ports, total_combos, num_batches, batch_size
    )

    state = load_state(Path(args.state_file))
    state_hosts = state.get("hosts", {})

    combos, progress_plan = next_batch(hosts, ports, state_hosts, batch_size)
    if not combos:
        logger.info("All VNC host/port pairs already scanned. Nothing to do.")
        return

    random.shuffle(combos)
    ensure_output(Path(args.output))

    findings = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_map = {
            executor.submit(scan_port, ip, port, timeout, base_delay, jitter): (domain, ip, port)
            for domain, ip, port in combos
        }
        for future in as_completed(future_map):
            domain, ip, port = future_map[future]
            banner = future.result()
            if banner:
                findings.append((domain, ip, port, "VNC_EXPOSED", banner.strip()))
                logger.info("VNC exposed: %s:%s (%s)", ip, port, domain)

    if findings:
        with Path(args.output).open("a", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerows(findings)

    # Update state to reflect processed combos
    for ip, count in progress_plan.items():
        prev = state_hosts.get(ip, 0)
        state_hosts[ip] = min(prev + count, len(ports))

    state["hosts"] = state_hosts
    state["last_run"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    state["last_batch_size"] = len(combos)
    save_state(Path(args.state_file), state)
    logger.info(
        "VNC batch complete. Scanned %d combos across %d hosts; %d exposures found.",
        len(combos),
        len(progress_plan),
        len(findings),
    )


if __name__ == "__main__":
    main()
