import dns.resolver
import ipaddress
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# DNS record types to check
RECORD_TYPES = ["A", "AAAA", "MX", "CNAME"]

def is_internal_ip(value):
    try:
        ip_obj = ipaddress.ip_address(value)
        return (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_link_local or
            ip_obj.is_reserved or
            ip_obj.is_multicast
        )
    except ValueError:
        return False

def resolve_dns(domain):
    internal_hits = []

    for rtype in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=3)
            for rdata in answers:
                value = None
                if rtype in ["A", "AAAA"]:
                    value = rdata.address
                elif rtype == "MX":
                    value = str(rdata.exchange).rstrip('.')
                elif rtype == "CNAME":
                    value = str(rdata.target).rstrip('.')

                if value:
                    if is_internal_ip(value):
                        internal_hits.append((rtype, value))
                    elif rtype in ["MX", "CNAME"]:
                        try:
                            sub_answers = dns.resolver.resolve(value, "A", lifetime=3)
                            for sub in sub_answers:
                                if is_internal_ip(sub.address):
                                    internal_hits.append((rtype, f"{value} -> {sub.address}"))
                        except:
                            continue
        except:
            continue

    return domain, internal_hits

def main():
    parser = argparse.ArgumentParser(description="DNS Internal IP Exposure Scanner")
    parser.add_argument("-i", "--input", required=True, help="Input file with domains")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads (default: 20)")
    args = parser.parse_args()

    with open(args.input, "r") as f:
        domains = [line.strip() for line in f if line.strip()]

    results = {}

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_domain = {executor.submit(resolve_dns, domain): domain for domain in domains}
        for future in tqdm(as_completed(future_to_domain), total=len(future_to_domain), desc="Scanning DNS"):
            domain, findings = future.result()
            if findings:
                results[domain] = findings

    if args.output:
        with open(args.output, "w") as out:
            for domain, entries in results.items():
                for record_type, value in entries:
                    out.write(f"{domain} [{record_type}] → {value}\n")
        print(f"\n[+] Results written to {args.output}")
    else:
        print("\n[+] Exposed Internal IPs:")
        for domain, entries in results.items():
            print(f"\n[!] {domain}")
            for record_type, value in entries:
                print(f"    [{record_type}] → {value}")

if __name__ == "__main__":
    main()