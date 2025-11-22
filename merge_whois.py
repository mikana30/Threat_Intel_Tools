#!/usr/bin/env python3
import argparse
import pandas as pd
import os
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def main():
    parser = argparse.ArgumentParser(description="Merge reconnaissance data with WHOIS information.")
    parser.add_argument("--recon-file", required=True, help="Path to the main reconnaissance CSV file (e.g., Recon_out.csv).")
    parser.add_argument("--whois-file", required=True, help="Path to the WHOIS results CSV file (e.g., whois_results.csv).")
    parser.add_argument("--output-file", required=True, help="Path to the output enriched CSV file.")
    args = parser.parse_args()

    # Load reconnaissance data
    try:
        recon_df = pd.read_csv(args.recon_file, dtype=str, keep_default_na=False)
        logging.info(f"Loaded {len(recon_df)} records from {args.recon_file}")
    except FileNotFoundError:
        logging.error(f"Reconnaissance file not found: {args.recon_file}")
        exit(1)
    except Exception as e:
        logging.error(f"Error loading reconnaissance file {args.recon_file}: {e}")
        exit(1)

    # Load WHOIS data
    try:
        whois_df = pd.read_csv(args.whois_file, dtype=str, keep_default_na=False)
        logging.info(f"Loaded {len(whois_df)} records from {args.whois_file}")
    except FileNotFoundError:
        logging.warning(f"WHOIS file not found: {args.whois_file}. Proceeding without WHOIS enrichment.")
        whois_df = pd.DataFrame(columns=["ip", "whois_info"]) # Create empty DataFrame
    except Exception as e:
        logging.error(f"Error loading WHOIS file {args.whois_file}: {e}. Proceeding without WHOIS enrichment.")
        whois_df = pd.DataFrame(columns=["ip", "whois_info"]) # Create empty DataFrame

    logging.info(f"Merging {len(recon_df)} recon records with {len(whois_df)} WHOIS records.")

    # Merge DataFrames on 'ip' column
    # Use a left merge to keep all recon data and add WHOIS info where available
    merged_df = pd.merge(recon_df, whois_df, on="ip", how="left")

    # Fill NaN values in 'whois_info' with a default message
    merged_df['whois_info'].fillna('No WHOIS data available', inplace=True)

    # Save the enriched data to a new CSV file
    output_dir = os.path.dirname(args.output_file)
    os.makedirs(output_dir, exist_ok=True)
    merged_df.to_csv(args.output_file, index=False)
    logging.info(f"Successfully created enriched output file with {len(merged_df)} records at: {args.output_file}")

if __name__ == "__main__":
    main()