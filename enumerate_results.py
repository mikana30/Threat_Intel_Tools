#!/usr/bin/env python3
import sys, pandas as pd, json

if len(sys.argv) != 3:
    print("Usage: enumerate_results.py <input_csv> <output_json>")
    sys.exit(1)

inp, outp = sys.argv[1], sys.argv[2]
try:
    df = pd.read_csv(inp)
    records = df.to_dict(orient="records")
    with open(outp, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)
    print(f"[EXPORT] {inp} -> {outp} ({len(records)} records)")
except Exception as e:
    print(f"[ERROR] Failed exporting {inp}: {e}", file=sys.stderr)
    sys.exit(2)
