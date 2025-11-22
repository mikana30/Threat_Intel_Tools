import requests
import csv
from tqdm import tqdm
import argparse
import time
import concurrent.futures
from threading import Lock

def query_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; crtsh-bot/1.0)"
    }
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            return r.json()
        else:
            print(f"[WARN] HTTP {r.status_code} for {domain}")
    except Exception as e:
        print(f"[ERROR] Exception for {domain}: {e}")
    return []

def process_domain(domain):
    domain = domain.strip().lower().lstrip("*.")  # Remove wildcard if present
    entries = query_crtsh(domain)
    print(f"[DEBUG] {domain}: {len(entries)} entries found")
    results = []
    for e in entries:
        results.append({
            "domain": domain,
            "common_name": e.get("common_name", ""),
            "name_value": e.get("name_value", ""),
            "issuer_name": e.get("issuer_name", ""),
            "not_before": e.get("not_before", ""),
            "not_after": e.get("not_after", "")
        })
    return results

def process_domain_with_delay(domain):
    """Process domain and add rate-limiting delay"""
    results = process_domain(domain)
    time.sleep(0.5)  # Reduced delay since we're using limited workers
    return results

def main():
    parser = argparse.ArgumentParser(description="CRT.sh Certificate Transparency Scraper")
    parser.add_argument('-i', '--input', required=True, help="Input file with domains (one per line)")
    parser.add_argument('-o', '--output', required=True, help="Output CSV file")
    args = parser.parse_args()

    with open(args.input) as f:
        domains = [line.strip() for line in f if line.strip()]

    all_results = []
    result_lock = Lock()

    # Process domains in parallel with controlled concurrency
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(process_domain_with_delay, d): d for d in domains}

        for future in tqdm(concurrent.futures.as_completed(futures), total=len(domains), desc="Processing domains"):
            try:
                results = future.result()
                with result_lock:
                    all_results.extend(results)
            except Exception as e:
                domain = futures[future]
                print(f"[ERROR] Failed to process {domain}: {e}")

    with open(args.output, "w", newline='') as csvfile:
        fieldnames = ["domain", "common_name", "name_value", "issuer_name", "not_before", "not_after"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in all_results:
            writer.writerow(row)

    print(f"[✓] Done. Results written to {args.output} ({len(all_results)} rows).")

if __name__ == "__main__":
    main()