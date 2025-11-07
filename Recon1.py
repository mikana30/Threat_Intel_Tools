import os
import subprocess
import shutil
import argparse
import csv
import time
import random
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from urllib.parse import urlparse

MAX_THREADS = 20
current_dir = Path.cwd()

def run_command(cmd, capture_output=True):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=capture_output, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {cmd}\nError: {e.stderr.strip()}")
        raise
    except Exception as e:
        logging.error(f"An exception occurred with command: {cmd}\nException: {e}")
        raise



def locate_tool(tool_name):
    try:
        path = run_command(f"which {tool_name}")
        if path:
            return path
        else:
            return None
    except subprocess.CalledProcessError:
        return None

def run_subdomz(domain, output_dir):
    logging.info(f"Running SubDomz for {domain}...")
    try:
        subdomz_path = "/home/kali/Desktop/threat_intel/Threat Intel Tools and Work Flow/SubDomz.sh"
        if not Path(subdomz_path).exists():
            logging.warning("SubDomz.sh not found at expected path. Skipping.")
            return []
        raw_out = output_dir / "subdomz_raw.txt"
        out_file = output_dir / "subdomz.txt"
        run_command(f'"{subdomz_path}" -d {domain} -o "{raw_out}"')
        results = []
        if raw_out.exists():
            with open(raw_out) as f:
                for line in f:
                    if domain in line.strip():
                        results.append(line.strip())
            raw_out.unlink()
        out_file.write_text("\n".join(results))
        return results
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

def run_assetfinder(domain, output_dir):
    logging.info(f"Running assetfinder for {domain}...")
    try:
        if shutil.which("assetfinder") is None:
            logging.warning("assetfinder not found. Skipping.")
            return []
        out_file = output_dir / "assetfinder.txt"
        result = run_command(f"assetfinder {domain} | grep -iP '^[^*]*?{domain}$' | sort -u")
        out_file.write_text(result)
        return result.splitlines()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

def run_subfinder(domain, output_dir):
    logging.info(f"Running subfinder for {domain}...")
    try:
        if shutil.which("subfinder") is None:
            logging.warning("subfinder not found. Skipping.")
            return []
        out_file = output_dir / "subfinder.txt"
        result = run_command(f"subfinder -d {domain} | grep -iP '^[^*]*?{domain}$' | sort -u")
        out_file.write_text(result)
        return result.splitlines()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

def run_gau(domain, output_dir):
    try:
        if shutil.which("gau") is None:
            logging.warning("gau not found. Skipping.")
            return []
        out_file = output_dir / "gau.txt"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        run_command(f"gau {domain} --o \"{out_file.resolve()}\"")
        if out_file.exists():
            return out_file.read_text().splitlines()
        return []
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

def run_httpx(domains, output_dir, args):
    try:
        prober_script = current_dir / "http_prober.py"
        if not prober_script.exists():
            logging.warning("http_prober.py not found. Skipping HTTP probing.")
            return {}

        in_file = output_dir / "httpx_input.txt"
        out_file = output_dir / "httpx_output.txt"
        in_file.write_text("\n".join(domains))

        # Build the command with gentle options and properly quoted paths
        cmd = (
            f"python3 \"{prober_script}\" -i \"{in_file}\" -o \"{out_file}\" "
            f"-t {args.threads} --delay {args.probe_delay} --jitter {args.probe_jitter} --quiet"
        )
        if args.probe_user_agent:
            cmd += f" --user-agent \"{args.probe_user_agent}\""
        
        run_command(cmd)

        results = {}
        if out_file.exists():
            with open(out_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    results[row['url']] = {"status": row['status_code'], "title": row['title']}
        return results
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logging.error(f"Error running http_prober.py: {e}")
        return {}

import re

def resolve_domain(domain):
    time.sleep(random.uniform(0.1, 0.5))
    try:
        result = run_command(f"dig {domain} +short")
        # Filter for valid IP addresses only
        ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        ips = [line.strip() for line in result.splitlines() if ip_pattern.match(line.strip())]
        return domain, ips
    except subprocess.CalledProcessError:
        return domain, []


def process_domain(domain, args, base_output_dir):
    output_dir = base_output_dir / "recon_outputs" / domain
    output_dir.mkdir(exist_ok=True, parents=True)

    logging.info(f"Running subdomain enumeration for: {domain}")
    subdomz = run_subdomz(domain, output_dir)
    assetfinder = run_assetfinder(domain, output_dir)
    subfinder = run_subfinder(domain, output_dir)

    all_domains = set(map(str.lower, subdomz + assetfinder + subfinder))

    if not all_domains:
        logging.warning(f"No subdomains found for {domain}.")
        return

    # Optional GAU grab
    gau_urls = []
    if args.gau:
        logging.info(f"Running gau for {domain} ...")
        gau_urls = run_gau(domain, output_dir)
    
    # NEW: Parse gau URLs to find new subdomains
    gau_domains = set()
    if args.gau and gau_urls:
        logging.info(f"Parsing {len(gau_urls)} URLs from gau...")
        
        # Heuristic to find the base domain for discovery.
        # For 'www6.slac.stanford.edu', base becomes 'slac.stanford.edu'
        # For 'google.com', base remains 'google.com'
        parts = domain.split('.')
        if len(parts) > 2:
            base_domain = '.'.join(parts[-3:])
        else:
            base_domain = domain
        
        logging.info(f"Using '{base_domain}' as the base for discovering new subdomains from gau.")
        base_domain_suffix = f".{base_domain}"

        for url in gau_urls:
            try:
                hostname = urlparse(url).hostname
                if hostname:
                    hostname_lower = hostname.lower()
                    # Check if it's the base domain itself or a valid subdomain of it
                    if hostname_lower == base_domain or hostname_lower.endswith(base_domain_suffix):
                        gau_domains.add(hostname_lower)
            except Exception:
                continue # Ignore any URL parsing errors
    
    if gau_domains:
        logging.info(f"Found {len(gau_domains.difference(all_domains))} new subdomains from gau.")
        all_domains.update(gau_domains) # Add the new domains to the main set
    
    if not all_domains:
        logging.warning(f"No subdomains found for {domain}.")
        return

    all_path = output_dir / "all_domains.txt"
    all_path.write_text("\n".join(sorted(all_domains)))

    logging.info(f"Resolving domains for: {domain}")
    resolved = []
    domain_ips = {}
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(resolve_domain, d): d for d in all_domains}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Resolving"):
            d, ips = future.result()
            if ips:
                resolved.append(d)
                domain_ips[d] = ips

    # HTTP probing if requested
    httpx_results = {}
    if args.httpx and resolved:
        logging.info(f"Running HTTP prober on resolved domains...")
        httpx_results = run_httpx(resolved, output_dir, args)

    # WHOIS logic is now decoupled. We will collect all unique IPs instead.
    all_unique_ips = set()
    for ip_list in domain_ips.values():
        all_unique_ips.update(ip_list)

    # Write all unique IPs to a single file in the base output directory
    # This file will be the input for the new distributed_whois.py script
    if all_unique_ips:
        ip_output_file = base_output_dir / "all_resolved_ips.txt"
        with open(ip_output_file, "a", encoding="utf-8") as f:
            for ip in sorted(list(all_unique_ips)):
                f.write(f"{ip}\n")

    # Write CSV output
    csv_file = output_dir / f"{domain}_recon.csv"
    with open(csv_file, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["domain", "ip", "http_status", "http_title"] # whois_info is removed
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for d in resolved:
            ips = domain_ips.get(d, [])
            http_info = {}
            for url, info in httpx_results.items():
                if d in url:
                    http_info = info
                    break

            if ips:
                for ip in ips:
                    writer.writerow({
                        "domain": d,
                        "ip": ip,
                        "http_status": http_info.get("status", ""),
                        "http_title": http_info.get("title", ""),
                    })
            else:
                writer.writerow({
                    "domain": d,
                    "ip": "",
                    "http_status": http_info.get("status", ""),
                    "http_title": http_info.get("title", ""),
                })

    logging.info(f"Recon CSV saved: {csv_file}")

def main():
    parser = argparse.ArgumentParser(description="Robust subdomain recon tool")
    parser.add_argument("-d", "--domain", help="Single domain to scan")
    parser.add_argument("-f", "--file", help="File with list of domains")
    parser.add_argument("--gau", action="store_true", help="Run gau (archived URLs)")
    parser.add_argument("--httpx", action="store_true", help="Run httpx (HTTP probing)")
    parser.add_argument("--deep", action="store_true", help="Enable deep scan (future use)")
    parser.add_argument("--threads", type=int, default=20, help="Number of threads for concurrent operations")
    parser.add_argument("--probe-delay", type=float, default=1.0, help="Base delay for HTTP prober")
    parser.add_argument("--probe-jitter", type=float, default=0.5, help="Jitter for HTTP prober")
    parser.add_argument("--probe-user-agent", help="User-Agent for HTTP prober")
    parser.add_argument("-o", "--output-dir", help="Base directory for all output", default="outputs")
    args = parser.parse_args()

    global MAX_THREADS
    MAX_THREADS = args.threads

    # Setup logging
    log_dir = current_dir / "logs"
    log_dir.mkdir(exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_dir / "recon1.log", mode='w'),
            logging.StreamHandler()
        ]
    )

    base_output_dir = Path(args.output_dir).expanduser()
    base_output_dir.mkdir(parents=True, exist_ok=True)
    base_output_dir = base_output_dir.resolve()

    if args.domain:
        process_domain(args.domain, args, base_output_dir)
    elif args.file:
        if not Path(args.file).exists():
            logging.error(f"Input file {args.file} not found.")
            return
        with open(args.file) as f:
            for domain in f:
                domain = domain.strip()
                if domain:
                    process_domain(domain, args, base_output_dir)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

