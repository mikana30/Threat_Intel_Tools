import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import argparse
import csv
import random
import threading

COMMON_ADMIN_PATHS = [
    'admin', 'administrator', 'admin/login', 'adminpanel', 'login', 'user/login',
    'wp-admin', 'cpanel', 'manage', 'admin.php', 'login.php', 'admin/login.php',
    'dashboard', 'admin_area', 'backend', 'moderator', 'admin_console'
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:112.0) Gecko/20100101 Firefox/112.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 11; Pixel 4 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36"
]

VERIFY_SSL = False
thread_local = threading.local()

def get_session():
    if not hasattr(thread_local, "session"):
        thread_local.session = requests.Session()
    return thread_local.session

def normalize_domain(domain, scheme_preference='both'):
    domain = domain.strip().lower().replace('http://', '').replace('https://', '').strip('/')
    urls = []
    if scheme_preference in ['https', 'both']:
        urls.append('https://' + domain)
    if scheme_preference in ['http', 'both']:
        urls.append('http://' + domain)
    return urls

def check_path(domain, path, timeout):
    url = urljoin(domain, path)
    headers = {
        'User-Agent': random.choice(USER_AGENTS)
    }
    try:
        session = get_session()
        response = session.get(url, headers=headers, timeout=timeout, verify=VERIFY_SSL, allow_redirects=True)
        status = response.status_code
        if status in [200, 301, 302, 401, 403]:
            return (domain, url, f"Status: {status}")
    except requests.RequestException as e:
        print(f"[!] Error accessing {url}: {str(e).split(':')[0]}")
    return None

def check_domain(domain_timeout_tuple):
    domain, timeout = domain_timeout_tuple
    results = []
    for path in COMMON_ADMIN_PATHS:
        result = check_path(domain, path, timeout)
        if result:
            results.append(result)
    return results

def main():
    parser = argparse.ArgumentParser(description="🛡️ Fast & Stealthy Admin Page Finder (CSV Output)")
    parser.add_argument('-i', '--input', required=True, help='Input file with domains (one per line)')
    parser.add_argument('-o', '--output', required=True, help='Output CSV file')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of concurrent threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=5, help='Timeout per request in seconds (default: 5)')
    parser.add_argument('--https-only', action='store_true', help='Only scan using HTTPS')
    parser.add_argument('--http-only', action='store_true', help='Only scan using HTTP')
    args = parser.parse_args()

    scheme_preference = 'both'
    if args.https_only:
        scheme_preference = 'https'
    elif args.http_only:
        scheme_preference = 'http'

    with open(args.input, 'r') as f:
        raw_domains = [line.strip() for line in f if line.strip()]

    domains = []
    for domain in raw_domains:
        domains.extend(normalize_domain(domain, scheme_preference))

    print(f"\n🔍 Scanning {len(domains)} domains × {len(COMMON_ADMIN_PATHS)} paths using {args.threads} threads...\n")

    results = []
    domain_tasks = [(domain, args.timeout) for domain in domains]
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for res_batch in tqdm(executor.map(check_domain, domain_tasks), total=len(domain_tasks), desc="Scanning"):
            if res_batch:
                results.extend(res_batch)

    with open(args.output, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["domain", "url", "status"])
        writer.writerows(results)

    print(f"\n✅ Scan complete. Results saved to: {args.output}")

if __name__ == "__main__":
    main()