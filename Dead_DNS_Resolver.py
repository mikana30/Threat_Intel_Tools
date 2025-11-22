import argparse
import csv
import socket
import subprocess
import re
import ssl
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from datetime import datetime

socket.setdefaulttimeout(5)

def resolve_target(target):
    try:
        socket.gethostbyname(target)
        return True
    except socket.gaierror:
        return False

def identify_service(target):
    target = target.lower()
    if ".s3.amazonaws.com" in target or target.endswith(".amazonaws.com") and "s3" in target:
        return "AWS S3"
    elif ".cloudfront.net" in target:
        return "AWS CloudFront"
    elif "compute.amazonaws.com" in target or re.search(r"ec2-\d+-\d+-\d+-\d+\.compute", target):
        return "AWS EC2"
    elif "elb.amazonaws.com" in target:
        return "AWS ELB"
    return "Unknown AWS Service" if target.endswith(".amazonaws.com") else "Non-AWS"

def check_takeover(service, target):
    try:
        result = subprocess.run(
            ["curl", "-s", "-I", "--max-time", "5", f"http://{target}"],
            capture_output=True, text=True
        )
        headers = result.stdout.lower()
        if service == "AWS S3" and "nosuchbucket" in headers:
            return "Possible takeover (NoSuchBucket)"
        elif service == "AWS CloudFront" and "nosuchdistribution" in headers:
            return "Possible takeover (NoSuchDistribution)"
        elif "server" in headers and "amazon" in headers and "error" in headers:
            return "Possible takeover (AWS error page)"
    except Exception:
        pass
    return "No obvious takeover"

def get_ssl_info(target):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                cn = subject.get('commonName', '')
                issuer_org = issuer.get('organizationName', '')
                expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                return cn, issuer_org, expiry_date.strftime("%Y-%m-%d")
    except Exception:
        return "", "", ""
    
def get_historical_dns(target):
    try:
        url = f"https://crt.sh/?q={target}&output=json"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data:
                dates = sorted(set([entry['not_before'] for entry in data]))
                first_seen = dates[0][:10] if dates else ""
                last_seen = dates[-1][:10] if dates else ""
                return first_seen, last_seen
    except Exception:
        pass
    return "", ""

def investigate_record(row):
    domain = row["domain"].strip()
    record_type = row["type"].strip()
    target = row["target"].strip()
    ip = row["ip"].strip()

    resolvable = resolve_target(target)
    service = identify_service(target)
    takeover_status = check_takeover(service, target) if resolvable else "NXDOMAIN (safe to remove)"
    ssl_cn, ssl_issuer, ssl_expiry = get_ssl_info(target) if resolvable else ("", "", "")
    first_seen, last_seen = get_historical_dns(target)

    return {
        "domain": domain,
        "type": record_type,
        "target": target,
        "ip": ip,
        "resolves": "Yes" if resolvable else "No",
        "service": service,
        "takeover_status": takeover_status,
        "ssl_cn": ssl_cn,
        "ssl_issuer": ssl_issuer,
        "ssl_expiry": ssl_expiry,
        "first_seen": first_seen,
        "last_seen": last_seen
    }

def process_csv(input_file, output_file, threads):
    with open(input_file, newline='') as csvfile:
        reader = list(csv.DictReader(csvfile))
        results = []

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(investigate_record, row): row for row in reader if row.get("stale", "").strip().lower() == "true"
            }
            for future in tqdm(as_completed(futures), total=len(futures), desc="Investigating stale DNS"):
                results.append(future.result())

    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = [
            "domain", "type", "target", "ip", "resolves", "service",
            "takeover_status", "ssl_cn", "ssl_issuer", "ssl_expiry",
            "first_seen", "last_seen"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"[✓] Investigation results saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Investigate stale DNS records for takeover risks, SSL, and history")
    parser.add_argument("-i", "--input", required=True, help="Input CSV file with stale DNS results")
    parser.add_argument("-o", "--output", required=True, help="Output CSV file for investigation results")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    args = parser.parse_args()

    process_csv(args.input, args.output, args.threads)
