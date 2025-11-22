#!/usr/bin/env python3
import argparse
import csv
import json
import logging
from pathlib import Path

import requests

from dev_mode import get_target_cap, load_env_settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("logs/http_probe.log", mode="w"), logging.StreamHandler()],
)
logger = logging.getLogger("http_probe")


def probe(url: str, timeout: float, headers: dict | None) -> tuple[str, int | None, str]:
    try:
        resp = requests.get(url, timeout=timeout, headers=headers, verify=False)
        return url, resp.status_code, resp.headers.get("Server", "")
    except Exception:
        return url, None, ""


def main():
    parser = argparse.ArgumentParser(description="Lightweight HTTP probe")
    parser.add_argument("--resolved-json", required=True, help="resolved.json path")
    parser.add_argument("--output", required=True, help="CSV output path")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--scheme", action="append", default=["https", "http"])
    parser.add_argument("--header", action="append", help="Custom header KEY:VALUE")
    parser.add_argument(
        "--env-config",
        default="config/environment.yml",
        help="Optional environment config to enforce dev caps",
    )
    args = parser.parse_args()

    resolved = json.loads(Path(args.resolved_json).read_text())
    hosts = sorted(resolved.keys())

    env_settings = load_env_settings(Path(args.env_config))
    cap = get_target_cap(env_settings)
    if cap:
        hosts = hosts[:cap]
        logger.info("Dev cap active (%d) in http_probe - limiting host list.", cap)

    headers = {}
    if args.header:
        for item in args.header:
            if ":" in item:
                key, value = item.split(":", 1)
                headers[key.strip()] = value.strip()

    rows = []
    for host in hosts:
        for scheme in args.scheme:
            url = f"{scheme}://{host}"
            rows.append(probe(url, args.timeout, headers))

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "status", "server"])
        writer.writerows(rows)


if __name__ == "__main__":
    main()
