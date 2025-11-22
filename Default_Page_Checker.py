import requests
import argparse
import threading
from queue import Queue
from tqdm import tqdm
import csv
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Known default page signatures
default_signatures = {
    "apache": ["It works!", "Apache2 Ubuntu Default Page"],
    "nginx": ["Welcome to nginx!"],
    "iis": ["IIS Windows Server", "Welcome to IIS"],
    "tomcat": ["Apache Tomcat"],
    "ngrok": ["Tunnel", "ngrok"]
}

results = []
lock = threading.Lock()

def is_default_page(content):
    for server, sigs in default_signatures.items():
        if any(sig.lower() in content.lower() for sig in sigs):
            return server
    return None

def check_url(q, progress):
    while not q.empty():
        base_url = q.get()
        urls_to_try = []

        if not base_url.startswith("http"):
            urls_to_try = [f"http://{base_url}", f"https://{base_url}"]
        else:
            scheme = "https" if base_url.startswith("https") else "http"
            other = "https" if scheme == "http" else "http"
            stripped = base_url.replace("http://", "").replace("https://", "")
            urls_to_try = [f"{scheme}://{stripped}", f"{other}://{stripped}"]

        for url in urls_to_try:
            try:
                response = requests.get(url, timeout=5, verify=False)
                server_type = is_default_page(response.text)
                if server_type:
                    result = {
                        "url": url,
                        "status": "default page",
                        "server": server_type
                    }
                    with lock:
                        results.append(result)
                    break  # No need to check other scheme
            except Exception:
                continue  # Try the next protocol

        progress.update(1)
        q.task_done()

def main():
    parser = argparse.ArgumentParser(description="Check for default web server pages.")
    parser.add_argument('-i', '--input', required=True, help='Input file with domains')
    parser.add_argument('-o', '--output', help='Output file (CSV format)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    args = parser.parse_args()

    with open(args.input, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]

    q = Queue()
    for url in urls:
        q.put(url)

    progress = tqdm(total=len(urls), desc="Scanning", ncols=75)

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=check_url, args=(q, progress))
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()
    progress.close()

    # Output results to CSV
    output_fields = ["url", "status", "server"]
    if results:
        if args.output:
            with open(args.output, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=output_fields)
                writer.writeheader()
                writer.writerows(results)
        else:
            writer = csv.DictWriter(sys.stdout, fieldnames=output_fields)
            writer.writeheader()
            writer.writerows(results)

if __name__ == "__main__":
    main()
