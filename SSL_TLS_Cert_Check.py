import ssl
import socket
from datetime import datetime
import concurrent.futures
import csv
from tqdm import tqdm
import argparse

def get_cert_expiry(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                exp_date_str = cert['notAfter']
                exp_date = datetime.strptime(exp_date_str, '%b %d %H:%M:%S %Y %Z')
                days_left = (exp_date - datetime.now(datetime.UTC)).days
                return (domain, exp_date_str, days_left, "ok")
    except Exception as e:
        return (domain, None, None, str(e))

def main():
    parser = argparse.ArgumentParser(description="Check SSL certificate expiration dates for domains.")
    parser.add_argument("-i", "--input", required=True, help="Input file with domains (one per line)")
    parser.add_argument("-o", "--output", required=True, help="Output CSV file")
    args = parser.parse_args()

    with open(args.input) as f:
        domains = [line.strip() for line in f if line.strip()]

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = [executor.submit(get_cert_expiry, d) for d in domains]
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(domains), desc="Checking certs"):
            results.append(future.result())

    with open(args.output, "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["domain", "cert_expiry", "days_until_expiry", "status"])
        writer.writerows(results)

    print(f"[✓] Certificate scan complete. Results saved to: {args.output}")

if __name__ == "__main__":
    main()
