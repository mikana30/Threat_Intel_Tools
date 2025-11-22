import socket
import concurrent.futures
from tqdm import tqdm
import csv
import argparse

# Expanded list of risky cloud/misconfig service ports
PORTS_TO_CHECK = {
    6443: ("Kubernetes Dashboard", "Extreme"),
    9200: ("Elasticsearch", "High"),
    27017: ("MongoDB", "High"),
    2379: ("Etcd", "High"),
    5984: ("CouchDB", "High"),
    15672: ("RabbitMQ Management", "Medium"),
    11211: ("Memcached", "High"),
    5000: ("Docker API", "Extreme"),
    8086: ("InfluxDB", "Medium"),
    8888: ("Jupyter Notebook", "High")
}

def is_port_open(ip, port, timeout=2):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except:
        return False

def grab_banner(ip, port, timeout=2):
    """Grab first few bytes from the open port to identify the service/version."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                banner = s.recv(1024).decode(errors="ignore").strip()
                return banner if banner else "No banner"
            except socket.timeout:
                return "No response"
    except:
        return "Error grabbing banner"

def scan_target(domain, ip):
    results = []
    for port, (service, risk) in PORTS_TO_CHECK.items():
        if is_port_open(ip, port):
            banner = grab_banner(ip, port)
            results.append((domain, ip, port, service, banner, risk))
    return results

def main():
    parser = argparse.ArgumentParser(
        description="Exposed Management Services Scanner (Passive Port Scan)",
        epilog="NOTE: This is a passive port scan only. It does NOT test authentication or verify misconfigurations. "
               "All findings require manual validation to determine actual security risk."
    )
    parser.add_argument("-i", "--input", required=True, help="Input file (format: domain [IP])")
    parser.add_argument("-o", "--output", required=True, help="Output CSV file")
    args = parser.parse_args()

    print("=" * 70)
    print("IMPORTANT DISCLAIMER:")
    print("This scanner performs PASSIVE reconnaissance only (port scanning).")
    print("It does NOT:")
    print("  - Test authentication or access controls")
    print("  - Attempt to access services or verify misconfigurations")
    print("  - Determine if services are properly secured")
    print("")
    print("All findings are POTENTIAL risks requiring manual validation.")
    print("Active security testing requires proper authorization.")
    print("=" * 70)
    print()

    # Load targets
    targets = []
    with open(args.input) as f:
        for line in f:
            if line.strip():
                parts = line.strip().split()
                if len(parts) == 2:
                    domain, ip = parts
                else:
                    domain = parts[0]
                    try:
                        ip = socket.gethostbyname(domain)
                    except:
                        continue
                targets.append((domain, ip))

    # Scan
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = [executor.submit(scan_target, domain, ip) for domain, ip in targets]
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Scanning"):
            res = future.result()
            if res:
                results.extend(res)

    # Save output
    with open(args.output, "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["domain", "ip", "port", "service", "banner", "risk"])
        writer.writerows(results)

    print(f"\n✅ Scan complete. Results saved to: {args.output}")
    if results:
        print(f"⚠️  Found {len(results)} exposed management service(s).")
        print("⚠️  REMINDER: These findings require manual validation to confirm actual risk.")

if __name__ == "__main__":
    main()
