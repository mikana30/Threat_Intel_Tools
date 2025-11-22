import requests
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from argparse import ArgumentParser
from tqdm import tqdm
import random
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {"User-Agent": "PassiveGitLeakScanner/1.1"}
TIMEOUT = 6
THREADS = 10

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "curl/7.79.1",
    "Wget/1.21.1 (linux-gnu)"
]

CHECK_PATHS = [".git/config", ".git/HEAD"]

def check_git_leak(domain, debug=False):
    urls_to_check = []
    for path in CHECK_PATHS:
        urls_to_check.append(f"http://{domain}/{path}")
        urls_to_check.append(f"https://{domain}/{path}")

    for url in urls_to_check:
        headers = HEADERS.copy()
        headers["User-Agent"] = random.choice(USER_AGENTS)
        try:
            resp = requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=True, verify=False)
            content_type = resp.headers.get("Content-Type", "").lower()
            status_code = resp.status_code

            if debug:
                print(f"[DEBUG] {url} → {status_code} {resp.reason} | Content-Type: {content_type}")

            # Fully vulnerable
            if status_code == 200 and "[core]" in resp.text and "text" in content_type:
                return (domain, "Vulnerable", url, status_code, resp.reason)

            if status_code == 200 and "ref:" in resp.text and "text" in content_type:
                return (domain, "Vulnerable (HEAD)", url, status_code, resp.reason)

            # Protected but exists
            if status_code == 403:
                return (domain, "Potentially Protected", url, status_code, resp.reason)

            # Suspicious case
            if status_code == 200 and ".git" in url and "text" in content_type:
                return (domain, "Possible Leak", url, status_code, resp.reason)

        except requests.exceptions.RequestException as e:
            if debug:
                print(f"[DEBUG] Error for {url}: {e}")
            continue

    return (domain, "No Leak", "", None, None)

def load_domains(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def main(input_file, output_file, debug=False):
    domains = load_domains(input_file)
    results = []

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(check_git_leak, domain, debug): domain for domain in domains}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Scanning"):
            results.append(future.result())

    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "status", "leak_url", "status_code", "reason"])
        writer.writerows(results)

    print(f"[✓] Results saved to {output_file}")

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-i", "--input", required=True, help="Input file of domains")
    parser.add_argument("-o", "--output", required=True, help="Output CSV file")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()
    main(args.input, args.output, args.debug)
