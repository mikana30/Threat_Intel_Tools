import argparse
import requests
import re
import tldextract
import queue
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import csv

# ==== Initialization ====
init(autoreset=True)  # Colorama
result_queue = queue.Queue()
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ==== Request Sender ====
def SendRequest(domain):
    url = f'https://{domain}'
    redirectDomain = ""
    parentDomain = f"{tldextract.extract(domain).domain}.{tldextract.extract(domain).suffix}"
    responseError = False
    response = None

    httpErrorMessages = [
        "Failed to establish a new connection",
        "Name or service not known",
        "connect timeout",
        "Network is unreachable",
        "alert handshake failure",
        "No address associated with hostname",
        "Temporary failure in name resolution"
    ]

    print(f"[DEBUG] Checking {domain}")

    try:
        response = requests.get(url, allow_redirects=False, verify=False, timeout=5)
    except requests.exceptions.RequestException as e:
        if not any(msg in str(e) for msg in httpErrorMessages):
            match = re.search(r"host='(.*?)'", str(e))
            if match:
                redirectDomain = match.group(1)
            else:
                responseError = True
                print(f"[!] Unexpected error for {domain}: {e}")
        else:
            responseError = True

    if redirectDomain:
        redirectParentDomain = f"{tldextract.extract(redirectDomain).domain}.{tldextract.extract(redirectDomain).suffix}"
        if redirectParentDomain != parentDomain:
            color = Fore.BLUE if redirectDomain == "login.microsoftonline.com" else Fore.GREEN
            message = f"Original Domain: {domain} → RedirectDomain: {redirectDomain}"
            print(color + message + Style.RESET_ALL)
            result_queue.put({"original_domain": domain, "redirect_domain": redirectDomain})

    elif response:
        if 'Location' in response.headers:
            location = urlparse(response.headers['Location']).netloc
            if location:
                redirectParentDomain = f"{tldextract.extract(location).domain}.{tldextract.extract(location).suffix}"
                if redirectParentDomain != parentDomain:
                    color = Fore.BLUE if location == "login.microsoftonline.com" else Fore.GREEN
                    message = f"Original Domain: {domain} → Redirect URL: {location}"
                    print(color + message + Style.RESET_ALL)
                    result_queue.put({"original_domain": domain, "redirect_domain": location})
    elif responseError:
        message = f"[!] {domain}: No valid HTTPS or redirection"
        print(Fore.YELLOW + message + Style.RESET_ALL)

# ==== Main Thread Logic ====
def main():
    parser = argparse.ArgumentParser(description="Check subdomain redirects")
    parser.add_argument('-df', '--domainfile', type=str, help='File with list of domains')
    parser.add_argument('-d', '--domain', type=str, help='Single domain')
    parser.add_argument('-t', '--threads', type=int, help='Number of threads to use', default=5)
    parser.add_argument('-o', '--output', type=str, help='Optional output file to save results', default=None)
    args = parser.parse_args()

    if not args.domain and not args.domainfile:
        parser.error("❌ You must provide either -d for a domain or -df for a domain file")

    if args.domainfile:
        try:
            with open(args.domainfile, 'r') as f:
                items_to_process = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(Fore.RED + f"[!] File not found: {args.domainfile}")
            return
    else:
        items_to_process = [args.domain]

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_item = {executor.submit(SendRequest, item): item for item in items_to_process}
        for future in as_completed(future_to_item):
            item = future_to_item[future]
            try:
                future.result()
            except Exception as exc:
                print(Fore.RED + f"[!] {item} caused exception: {exc}" + Style.RESET_ALL)

    # ==== Save results to file if -o is provided ====
    if args.output:
        try:
            with open(args.output, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=["original_domain", "redirect_domain"])
                writer.writeheader()
                while not result_queue.empty():
                    writer.writerow(result_queue.get())
            print(Fore.CYAN + f"[✓] Results written to {args.output}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[✗] Could not save results: {e}" + Style.RESET_ALL)

# ==== Run Entry Point ====
if __name__ == "__main__":
    main()
