import argparse
import threading
import requests
import dns.resolver
from queue import Queue
from tqdm import tqdm
import csv
import time

# Expanded fingerprints
vulnerable_services = {
    "github.io": ["There isn't a GitHub Pages site here", "404"],
    "herokuapp.com": ["No such app", "Application error"],
    "amazonaws.com": ["NoSuchBucket", "Bucket not found"],
    "bitbucket.io": ["Repository not found"],
    "readthedocs.io": ["Unknown domain", "Page not found"],
    "fastly.net": ["Fastly error: unknown domain", "Fastly error"],
    "surge.sh": ["project not found", "404 Not Found"],
    "zendesk.com": ["Help Center Closed", "Oops", "not exist"]
}

results = []
lock = threading.Lock()
dns_cache = {}

def resolve_cname(subdomain):
    if subdomain in dns_cache:
        return dns_cache[subdomain]
    try:
        answers = dns.resolver.resolve(subdomain, 'CNAME', lifetime=5)
        for rdata in answers:
            cname = str(rdata.target).rstrip('.')
            dns_cache[subdomain] = cname
            return cname
    except Exception:
        dns_cache[subdomain] = None
        return None

def check_subdomain(subdomain, progress):
    try:
        cname = resolve_cname(subdomain)
        if not cname:
            progress.update(1)
            return

        for service, fingerprints in vulnerable_services.items():
            if service in cname:
                for proto in ["https://", "http://"]:
                    try:
                        response = requests.get(f"{proto}{subdomain}", timeout=6, allow_redirects=True)
                        page = response.text.lower()
                        for fp in fingerprints:
                            if fp.lower() in page:
                                with lock:
                                    results.append({
                                        "subdomain": subdomain,
                                        "cname": cname,
                                        "service": service,
                                        "http_status": response.status_code,
                                        "redirected_to": response.url if response.url != f"{proto}{subdomain}" else "",
                                        "fingerprint": fp,
                                        "status": "potentially vulnerable"
                                    })
                                return
                    except requests.RequestException:
                        continue
                break
    finally:
        progress.update(1)

def worker(q, progress):
    while not q.empty():
        domain = q.get()
        check_subdomain(domain, progress)
        q.task_done()

def main():
    parser = argparse.ArgumentParser(description="🔍 Check subdomains for takeover potential.")
    parser.add_argument('-i', '--input', required=True, help='Input file with subdomains')
    parser.add_argument('-o', '--output', required=True, help='CSV output file path')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    args = parser.parse_args()

    with open(args.input, 'r') as f:
        subdomains = [line.strip() for line in f if line.strip()]

    q = Queue()
    for subdomain in subdomains:
        q.put(subdomain)

    progress = tqdm(total=len(subdomains), desc="Checking", ncols=75)

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(q, progress))
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()
    progress.close()

    # Write CSV results
    with open(args.output, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["subdomain", "cname", "service", "http_status", "redirected_to", "fingerprint", "status"])
        for r in results:
            writer.writerow([
                r["subdomain"],
                r["cname"],
                r["service"],
                r["http_status"],
                r["redirected_to"],
                r["fingerprint"],
                r["status"]
            ])

    print(f"\n[✓] Found {len(results)} potentially vulnerable subdomain(s).")
    if results:
        print(f"[+] Results saved to: {args.output}")
    else:
        print("[!] No takeover candidates found.")

if __name__ == "__main__":
    main()
