import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from urllib.parse import urlparse, urljoin
import json
import random
import re
import time
import csv
from bs4 import BeautifulSoup

# --- Config ---
TIMEOUT = 6
MAX_RETRIES = 3
VERIFY_SSL = False

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:112.0) Gecko/20100101 Firefox/112.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.61 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko)'
]

DIR_LISTING_KEYWORDS = [
    'Index of', 'Parent Directory', 'Name', 'Last modified', 'Size',
    'Directory listing for', '<title>Index of'
]

COMMON_PATHS = ['/', '/uploads/', '/backup/', '/files/', '/export/', '/logs/', '/docs/', '/old/', '/test/']

SENSITIVE_EXT = {".env", ".sql", ".zip", ".tar.gz", ".log", ".db", ".pem", ".key", ".crt", ".bak"}

def is_valid_domain(domain):
    domain = domain.strip()
    return re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain) is not None

def normalize_url(line):
    line = line.strip()
    parsed = urlparse(line)
    netloc = parsed.netloc or parsed.path
    if not is_valid_domain(netloc):
        return []
    return [f'https://{netloc}', f'http://{netloc}']

def extract_listing_info(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    links = []
    for a in soup.find_all('a', href=True):
        href = a['href']
        text = a.get_text(strip=True)

        # Skip parent dir, JS links, hash routes
        if href in ['../', '/'] or href.startswith('?') or href.startswith('#') or href.startswith('javascript:'):
            continue

        file_url = urljoin(base_url, href)
        links.append({'text': text, 'href': file_url})
    return links if links else None

def head_file_info(session, url):
    try:
        headers = {'User-Agent': random.choice(USER_AGENTS)}
        r = session.head(url, headers=headers, timeout=TIMEOUT, verify=VERIFY_SSL, allow_redirects=True)
        if r.status_code == 200 and 'content-length' in r.headers:
            size = int(r.headers.get('content-length', 0))
            last_mod = r.headers.get('last-modified', '')
            return True, size, last_mod
    except:
        pass
    return False, None, None

def peek_file_content(session, url, size_limit=2048):
    try:
        headers = {'User-Agent': random.choice(USER_AGENTS), 'Range': f'bytes=0-{size_limit}'}
        r = session.get(url, headers=headers, timeout=TIMEOUT, verify=VERIFY_SSL, stream=True)
        if r.status_code in [200, 206]:
            return r.text[:size_limit].replace('\n', ' ').replace('\r', '')
    except:
        pass
    return ""

def classify_risk(filename):
    lower = filename.lower()
    for ext in SENSITIVE_EXT:
        if lower.endswith(ext):
            return "High"
    if "backup" in lower or "config" in lower or "secret" in lower:
        return "High"
    if lower.endswith(('.txt', '.csv', '.xml', '.json')):
        return "Medium"
    return "Low"

def is_directory_listing(session, url, strict=True):
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    for attempt in range(MAX_RETRIES):
        try:
            resp = session.get(url, headers=headers, timeout=TIMEOUT, verify=VERIFY_SSL, allow_redirects=True)
            if resp.status_code == 200 and 'text/html' in resp.headers.get('Content-Type', ''):
                html = resp.text.lower()
                match_count = sum(1 for keyword in DIR_LISTING_KEYWORDS if keyword.lower() in html)
                if (strict and match_count >= 3) or (not strict and match_count >= 1):
                    file_list = extract_listing_info(resp.text, url)
                    return True, 200, file_list
            return False, resp.status_code, None
        except requests.exceptions.Timeout:
            time.sleep(0.5)
            continue
        except requests.exceptions.ConnectionError:
            return False, None, "connection_error"
        except requests.exceptions.SSLError:
            return False, None, "ssl_error"
        except Exception as e:
            return False, None, f"error: {str(e).split(':')[0]}"
    return False, None, "timeout"

def scan_target(base_url, strict=True, delay=0):
    session = requests.Session()
    urls = normalize_url(base_url)
    results = []

    for root_url in urls:
        for path in COMMON_PATHS:
            full_url = urljoin(root_url, path)
            found, status, listing_info = is_directory_listing(session, full_url, strict=strict)
            if delay:
                time.sleep(delay)
            if found and listing_info:
                for f in listing_info:
                    accessible, size, last_mod = head_file_info(session, f['href'])
                    if accessible:
                        snippet = peek_file_content(session, f['href'])
                        risk = classify_risk(f['text'])
                        results.append({
                            "url": full_url,
                            "status": status,
                            "file_name": f['text'],
                            "file_url": f['href'],
                            "size": size,
                            "last_modified": last_mod,
                            "risk": risk,
                            "snippet": snippet
                        })
                return results
    return results

def save_results_to_csv(results, output_file):
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Directory URL", "Status", "File Name", "File URL", "Size", "Last Modified", "Risk", "Snippet"])
        for r in results:
            writer.writerow([
                r["url"], r["status"], r["file_name"], r["file_url"],
                r["size"], r["last_modified"], r["risk"], r["snippet"]
            ])

def main():
    parser = argparse.ArgumentParser(description="📂 Advanced Directory Listing Scanner with Risk Classification")
    parser.add_argument('-i', '--input', required=True, help='Input file (one domain or URL per line)')
    parser.add_argument('-o', '--output', required=True, help='Output file (CSV)')
    parser.add_argument('--threads', type=int, default=50, help='Concurrent threads (default: 50)')
    parser.add_argument('--delay', type=float, default=0.0, help='Delay (in seconds) between each request')
    parser.add_argument('--strict', action='store_true', help='Enable strict mode (require 3+ directory indicators)')
    args = parser.parse_args()

    with open(args.input, 'r') as f:
        raw_lines = [line.strip() for line in f if line.strip()]
    targets = [line for line in raw_lines if is_valid_domain(urlparse(line).netloc or line)]

    print(f"\n🔎 Scanning {len(targets)} targets using {args.threads} threads...\n")

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_target, target, args.strict, args.delay): target for target in targets}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Scanning"):
            try:
                result = future.result()
                results.extend(result)
            except Exception as e:
                print(f"[!] Unexpected exception: {e}")

    save_results_to_csv(results, args.output)
    print(f"\n✅ Results saved to: {args.output}")

if __name__ == "__main__":
    main()
