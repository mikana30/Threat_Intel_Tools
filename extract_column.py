#!/usr/bin/env python3
"""
extract_column.py
-----------------
Utility helper to export a single column from a CSV file into a newline-delimited
text file. Designed to support workflow stages that need simple domain lists
from richer reconnaissance outputs.
"""

import argparse
import sys
from pathlib import Path

import pandas as pd


def write_column(input_path: Path, column: str, output_path: Path, lowercase: bool) -> int:
    try:
        df = pd.read_csv(input_path, dtype=str)
    except FileNotFoundError:
        raise FileNotFoundError(f"Input file not found: {input_path}") from None
    except Exception as exc:
        raise RuntimeError(f"Failed to read {input_path}: {exc}") from exc

    normalized = {c.lower(): c for c in df.columns}
    lookup = column.lower()
    if lookup not in normalized:
        available = ", ".join(df.columns)
        raise ValueError(f"Column '{column}' not present in {input_path}. Available columns: {available}")

    series = df[normalized[lookup]].dropna().astype(str).str.strip()
    if lowercase:
        series = series.str.lower()

    unique_values = []
    seen = set()
    for value in series:
        if value and value not in seen:
            seen.add(value)
            unique_values.append(value)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(unique_values))
    return len(unique_values)


def main():
    parser = argparse.ArgumentParser(description="Extract a single column from a CSV into a text file.")
    parser.add_argument("--input", required=True, help="Path to the source CSV.")
    parser.add_argument("--column", required=True, help="Column name to extract (case-insensitive).")
    parser.add_argument("--output", required=True, help="Destination text file.")
    parser.add_argument("--no-lower", action="store_true", help="Preserve original casing (default lowercases).")
    args = parser.parse_args()

    try:
        count = write_column(Path(args.input), args.column, Path(args.output), lowercase=not args.no_lower)
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"[OK] Extracted {count} unique values from '{args.column}' into {args.output}")


if __name__ == "__main__":
    main()
