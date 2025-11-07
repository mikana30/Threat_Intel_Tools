#!/usr/bin/env python3
"""
Target Normalizer
-----------------
Reads a plain text targets file and writes a normalized JSON list with metadata.
"""

import argparse
import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def main():
    parser = argparse.ArgumentParser(description="Normalize targets into JSON")
    parser.add_argument("--input", required=True, help="targets.txt file")
    parser.add_argument("--output", required=True, help="Output JSON path")
    parser.add_argument("--tag", action="append", help="Optional tag to attach")
    args = parser.parse_args()

    target_file = Path(args.input)
    output_file = Path(args.output)
    targets = []
    for line in target_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(
            {
                "domain": line.lower(),
                "tags": args.tag or [],
            }
        )

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(targets, indent=2))
    logging.info("Wrote %d normalized targets to %s", len(targets), output_file)


if __name__ == "__main__":
    main()
