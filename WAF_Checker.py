import requests
import concurrent.futures
import csv
from tqdm import tqdm
import argparse

WAF_HEADERS = [
    "Server",
    "X-Waf-Status",
    "X-Sucuri-ID",
    "X-CDN",
    "X-Firewall",
    "X-Mod-Security",
    "X-Security",
    "X-Edge-IP"
]

def check_waf(domain):
    url = f"https://{domain}"
    try:
        r = requests.get(url, timeout=5)
        headers = r.headers
        waf_signs = {}
        for h in WAF_HEADERS:
            if h in headers:
                waf_signs[h] = headers[h]
        return (domain, bool(waf_signs), str(waf_signs))
    except Exception as e:
        return (domain, False, f"Error: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Detect WAF headers for domains.")
    parser.add_argument("-i", "--input", required=True, help="Input file with domain names")
    parser.add_argument("-o", "--output", required=True, help="Output CSV file")
    args = parser.parse_args()

    with open(args.input) as f:
        domains = [line.strip() for line in f if line.strip()]

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_waf, d) for d in domains]
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(domains), desc="Checking WAF"):
            results.append(future.result())

    with open(args.output, "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["domain", "waf_detected", "waf_headers"])
        writer.writerows(results)

    print(f"[✓] Scan complete. Results written to: {args.output}")

if __name__ == "__main__":
    main()