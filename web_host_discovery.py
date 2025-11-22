#!/usr/bin/env python3
"""
web_host_discovery.py
---------------------
Takes the consolidated Recon_out.csv file and extracts all unique, live URLs
that were discovered during the Recon1 phase. This script no longer performs
active probing; it simply processes the results from the initial scan.
"""
import pandas as pd
import argparse
import sys
from urllib.parse import urlparse

def main():
    parser = argparse.ArgumentParser(description="Extract live web hosts from Recon_out.csv.")
    parser.add_argument("-i", "--input", required=True, help="Input CSV file (e.g., Recon_out.csv).")
    parser.add_argument("-o", "--output", required=True, help="Output file for live web hosts (URLs).")
    args = parser.parse_args()

    try:
        df = pd.read_csv(args.input)
    except FileNotFoundError:
        print(f"[ERROR] Input file not found: {args.input}. Run the Recon1 and collect_recon stages first.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Failed to read {input_csv}: {e}", file=sys.stderr)
        sys.exit(1)

    live_urls = set()
    
    # Ensure the necessary columns exist
    if 'domain' in df.columns and 'http_status' in df.columns:
        # Filter for rows where our prober found a live host (http_status is not null/NA)
        live_hosts_df = df.dropna(subset=['http_status'])
        
        for domain in live_hosts_df['domain'].unique():
            # Default to https, as our prober tries that first.
            # The subsequent tools will handle protocol variations.
            live_urls.add(f"https://{domain}")

    if not live_urls:
        print("[WARN] No live URLs were extracted. The output file will be empty.", file=sys.stderr)

    with open(args.output, 'w') as f:
        for url in sorted(list(live_urls)):
            f.write(f"{url}\n")

    print(f"\n[✓] Extraction complete. Found {len(live_urls)} unique live URLs.")
    print(f"Results saved to: {args.output}")

if __name__ == "__main__":
    main()
