import dns.resolver
import argparse
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# Check SPF record
def analyze_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=3)
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.lower().startswith('v=spf1'):
                return {'record': txt, 'valid': True}
    except:
        pass
    return {'record': None, 'valid': False}

# Check DMARC record
def analyze_dmarc(domain):
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT', lifetime=3)
        for r in answers:
            txt = r.to_text().strip('"')
            if txt.lower().startswith('v=dmarc1'):
                return {'record': txt, 'valid': True}
    except:
        pass
    return {'record': None, 'valid': False}

# Check DKIM records using common selectors
DKIM_SELECTORS = ['default', 'google', 'mail']
def analyze_dkim(domain):
    findings = []
    for sel in DKIM_SELECTORS:
        try:
            answers = dns.resolver.resolve(f"{sel}._domainkey.{domain}", 'TXT', lifetime=3)
            for r in answers:
                txt = r.to_text().strip('"')
                if 'v=dkim1' in txt.lower():
                    findings.append({'selector': sel, 'record': txt})
        except:
            continue
    return findings

# Evaluate all three email auth records
def check_domain(domain):
    result = {
        'domain': domain,
        'spf_status': '',
        'spf_record': '',
        'dmarc_status': '',
        'dmarc_record': '',
        'dkim_status': '',
        'dkim_selectors': '',
        'dkim_records': ''
    }

    spf = analyze_spf(domain)
    result['spf_status'] = 'valid' if spf['valid'] else 'missing or invalid'
    result['spf_record'] = spf['record'] or ''

    dmarc = analyze_dmarc(domain)
    result['dmarc_status'] = 'valid' if dmarc['valid'] else 'missing or invalid'
    result['dmarc_record'] = dmarc['record'] or ''

    dkim = analyze_dkim(domain)
    if not dkim:
        result['dkim_status'] = 'no valid records'
    else:
        result['dkim_status'] = 'valid'
        result['dkim_selectors'] = ';'.join([d['selector'] for d in dkim])
        result['dkim_records'] = ';'.join([d['record'] for d in dkim])

    # Only return domains with something wrong
    if result['spf_status'] != 'valid' or result['dmarc_status'] != 'valid' or result['dkim_status'] != 'valid':
        return result
    return None

# Main logic
def main():
    parser = argparse.ArgumentParser(description="Check SPF, DKIM, DMARC configurations")
    parser.add_argument('-i', '--input', required=True, help='Input file with domains (one per line)')
    parser.add_argument('-o', '--output', required=True, help='Output CSV file')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Thread count (default 10)')
    args = parser.parse_args()

    with open(args.input) as f:
        domains = [d.strip() for d in f if d.strip()]

    findings = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(check_domain, d): d for d in domains}
        for future in tqdm(as_completed(futures), total=len(domains), desc="Auditing domains"):
            result = future.result()
            if result:
                findings.append(result)

    # Write to CSV
    with open(args.output, 'w', newline='') as out:
        writer = csv.DictWriter(out, fieldnames=[
            'domain',
            'spf_status', 'spf_record',
            'dmarc_status', 'dmarc_record',
            'dkim_status', 'dkim_selectors', 'dkim_records'
        ])
        writer.writeheader()
        for row in findings:
            writer.writerow(row)

    if findings:
        print(f"[!] Found {len(findings)} domain(s) with missing/invalid records.")
    else:
        print("[✓] All domains have valid SPF, DKIM, and DMARC configurations.")

if __name__ == "__main__":
    main()
