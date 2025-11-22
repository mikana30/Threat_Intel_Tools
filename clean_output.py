#!/usr/bin/env python3
"""
clean_output.py
---------------
Generic CSV cleaner used in multiple workflow stages.
- Reads an input CSV
- Flattens it to plain text
- Removes blanks / duplicates
- Writes a simple newline-delimited output file
"""

import sys
import pandas as pd

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.csv> <output.txt>", file=sys.stderr)
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    try:
        # Load CSV into DataFrame, forcing all data to be read as strings
        df = pd.read_csv(input_file, dtype=str)

        # Flatten into list of strings
        flattened = []
        for col in df.columns:
            flattened.extend(df[col].dropna().astype(str).str.strip())

        # Deduplicate while preserving order
        seen = set()
        cleaned = []
        for item in flattened:
            if item and item not in seen:
                cleaned.append(item)
                seen.add(item)

        # Write results
        with open(output_file, "w") as f:
            f.write("\n".join(cleaned))

        print(f"[INFO] Wrote {len(cleaned)} lines to {output_file}")

    except Exception as e:
        print(f"[ERROR] Failed to clean {input_file}: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
