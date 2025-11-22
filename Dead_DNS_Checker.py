import socket
import requests
import dns.resolver
import argparse
import csv
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

def is_ip_alive(ip):
    try:
        socket.create_connection((ip, 80), timeout=3)
        return True
    except:
        return False

def check_dns_staleness(domain):
    record = {"domain": domain, "stale": False, "type": "", "target": "", "ip": ""}
    try:
        # Check CNAME
        try:
            cname = dns.resolver.resolve(domain, 'CNAME')
            for rdata in cname:
                target = str(rdata.target).rstrip('.')
                try:
                    requests.get(f"http://{domain}", timeout=5)
                except requests.RequestException:
                    record["stale"] = True
                    record["type"] = "CNAME"
                    record["target"] = target
        except dns.resolver.NoAnswer:
            pass  # No CNAME record

        # Check A record
        try:
            ip_answers = dns.resolver.resolve(domain, 'A')
            for rdata in ip_answers:
                ip = rdata.address
                if not is_ip_alive(ip):
                    record["stale"] = True
                    record["type"] = "A"
                    record["ip"] = ip
        except dns.resolver.NoAnswer:
            pass

    except Exception:
        pass

    return record if record["stale"] else None

def main():
    parser = argparse.ArgumentParser(description="Find stale DNS records with threading.")
    parser.add_argument("-i", "--input", required=True, help="Input file with domains")
    parser.add_argument("-o", "--output", required=True, help="Output CSV file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads (default 10)")
    args = parser.parse_args()

    with open(args.input, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    stale_results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(check_dns_staleness, domain): domain for domain in domains}
        for future in tqdm(as_completed(futures), total=len(domains), desc="Checking domains"):
            result = future.result()
            if result:
                stale_results.append(result)

    with open(args.output, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "stale", "type", "target", "ip"])
        writer.writeheader()
        writer.writerows(stale_results)

    if stale_results:
        print(f"[✓] Found {len(stale_results)} stale DNS record(s).")
    else:
        print("[!] No stale records found.")

if __name__ == "__main__":
    main()