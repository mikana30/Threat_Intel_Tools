#!/usr/bin/env python3
"""
dev_cap_file.py
---------------
Utility script that truncates text/CSV files when development caps are enabled.

This lets the workflow keep long-running stages manageable in dev mode without
touching the original scripts. When the environment config (or TI_MODE env var)
switches to production, the script becomes a no-op.
"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

from dev_mode import get_target_cap, load_env_settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("logs/dev_cap_file.log", mode="w"), logging.StreamHandler()],
)
logger = logging.getLogger("dev_cap_file")


def truncate_lines(lines: list[str], cap: int, treat_as_csv: bool) -> list[str]:
    if not lines or cap <= 0:
        return lines

    if treat_as_csv:
        header = lines[0:1]
        data = lines[1:]
        return header + data[:cap]

    return lines[:cap]


def process_file(path: Path, cap: int) -> None:
    if not path.exists():
        logger.info("Skipping %s (missing).", path)
        return

    treat_as_csv = path.suffix.lower() == ".csv"
    contents = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    if not contents:
        logger.info("Skipping %s (empty).", path)
        return

    original_len = len(contents) - (1 if treat_as_csv else 0)
    if original_len <= cap:
        logger.info("Skipping %s (already <= cap)", path)
        return

    truncated = truncate_lines(contents, cap, treat_as_csv)
    path.write_text("\n".join(truncated) + ("\n" if truncated else ""), encoding="utf-8")
    logger.info(
        "Dev cap applied to %s: kept %d of %d rows.",
        path,
        min(original_len, cap),
        original_len,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Truncate files when dev caps are enabled.")
    parser.add_argument(
        "--env-config",
        default="config/environment.yml",
        help="Environment config that controls dev mode (default: config/environment.yml)",
    )
    parser.add_argument(
        "--file",
        dest="files",
        action="append",
        required=True,
        help="File to truncate. Repeat for multiple files.",
    )
    args = parser.parse_args()

    env_settings = load_env_settings(Path(args.env_config))
    cap = get_target_cap(env_settings)
    if not cap:
        logger.info("Dev cap disabled; leaving files untouched.")
        return

    for file_path in args.files:
        process_file(Path(file_path), cap)


if __name__ == "__main__":
    main()
