import socket
import argparse
import os
import sys
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed

# Load ports from config/ports.yml
def load_ports_config():
    config_path = os.path.join(os.path.dirname(__file__), "config", "ports.yml")
    if not os.path.exists(config_path):
        print(f"[WARNING] Config file not found at {config_path}, using default ports")
        return [21, 22, 23, 25, 53, 69, 80, 110, 111, 123, 135, 137, 138, 139, 143, 161, 179, 389, 443, 445, 512,
                513, 514, 873, 902, 903, 1025, 1080, 1194, 1433, 1521, 1723, 1900, 2049, 2375, 2376,
                3128, 3306, 3389, 3632, 4444, 5000, 5001, 5060, 5061, 5353, 5432, 5555, 5800, 5900, 5985,
                5986, 6000, 6379, 7001, 8000, 8008, 8080, 8081, 8089, 8443, 8888, 9000, 9001, 9200,
                11211, 27017, 27018, 49152, 65535, 20000, 1911, 47808, 502, 1962, 2404, 789, 31337,
                54321, 6666, 6667, 6668, 6669, 2323]

    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            return config.get('general', {}).get('ports', [])
    except Exception as e:
        print(f"[ERROR] Failed to load ports from config: {e}")
        return []

PORTS_TO_SCAN = load_ports_config()

# Check for dev mode cap
DEV_MODE = os.getenv('DEV_MODE', 'false').lower() == 'true'
DEV_CAP = int(os.getenv('DEV_CAP', '5'))

import csv

def scan_port_with_banner(domain, ip, port, timeout=1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                # Try to grab a banner
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    return {"domain": domain, "ip": ip, "port": port, "banner": banner if banner else "No banner"}
                except socket.timeout:
                    return {"domain": domain, "ip": ip, "port": port, "banner": "No banner (timeout)"}
                except Exception:
                    return {"domain": domain, "ip": ip, "port": port, "banner": "Banner read failed"}
    except socket.error:
        return None
    return None

def scan_targets(input_file, output_file, max_threads=100):
    with open(input_file, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]

    # Apply dev mode cap if enabled
    if DEV_MODE:
        targets = targets[:DEV_CAP]
        print(f"[DEV MODE] Capped targets to {len(targets)} entries")

    tasks = []
    results = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for entry in targets:
            try:
                domain, ip = entry.split(":")
                domain = domain.strip()
                ip = ip.strip()
            except ValueError:
                continue  # skip malformed lines

            for port in PORTS_TO_SCAN:
                tasks.append(executor.submit(scan_port_with_banner, domain, ip, port))

        for future in as_completed(tasks):
            result = future.result()
            if result:
                print(result)
                results.append(result)

    if output_file:
        with open(output_file, 'w', newline='') as out:
            writer = csv.DictWriter(out, fieldnames=["domain", "ip", "port", "banner"])
            writer.writeheader()
            writer.writerows(results)
        print(f"[INFO] Results written to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fast threaded port scanner with banner grabbing.")
    parser.add_argument("-i", "--input", required=True, help="Input file with domain: IP")
    parser.add_argument("-o", "--output", help="Optional output file for results")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of concurrent threads (default: 100)")

    args = parser.parse_args()

    scan_targets(args.input, args.output, args.threads)
