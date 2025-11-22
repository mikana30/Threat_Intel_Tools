#!/usr/bin/env python3
"""
extract_domains_only.py
-----------------------
Extracts only the "Domain" column from a resolver CSV and writes the unique set
to an output text file. Defaults mirror the original workflow
(`outputs/DnsResolver_out.csv` -> `outputs/domains_only.txt`) but both paths are
now configurable so orchestrators can point at per-run directories.
"""

from __future__ import annotations

import argparse
import sys

import pandas as pd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract unique domains from a resolver CSV.")
    parser.add_argument(
        "--input",
        default="outputs/DnsResolver_out.csv",
        help="Resolver CSV to read (default: outputs/DnsResolver_out.csv)",
    )
    parser.add_argument(
        "--output",
        default="outputs/domains_only.txt",
        help="Destination text file (default: outputs/domains_only.txt)",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Truncate the output file before writing (default: append mode).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_file = args.input
    output_file = args.output

    try:
        df = pd.read_csv(input_file)
    except Exception as exc:  # pragma: no cover - simple CLI helper
        print(f"[ERROR] Failed to read {input_file}: {exc}", file=sys.stderr)
        sys.exit(1)

    df.columns = [c.lower() for c in df.columns]

    if "domain" not in df.columns:
        print(f"[ERROR] No 'domain' column found in {input_file}", file=sys.stderr)
        sys.exit(1)

    domains = (
        df["domain"]
        .dropna()
        .astype(str)
        .str.strip()
        .str.lower()
        .unique()
    )

    mode = "w" if args.overwrite else "a"
    with open(output_file, mode, encoding="utf-8") as f:
        if mode == "a":
            f.write("\n")
        f.write("\n".join(domains))

    print(f"[INFO] Extracted {len(domains)} domains to {output_file}")


if __name__ == "__main__":
    main()
