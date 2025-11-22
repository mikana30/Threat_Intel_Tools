#!/usr/bin/env python3
"""
Generate priority screenshot target list from security findings.
Only includes URLs that matter for security assessment.
"""
import csv
import sys
import argparse
from pathlib import Path

# Increase CSV field size limit to handle large fields
csv.field_size_limit(10 * 1024 * 1024)  # 10MB limit

def main():
    parser = argparse.ArgumentParser(
        description="Generate priority screenshot targets from security findings"
    )
    parser.add_argument("-i", "--input-dir", required=True, help="Directory containing scan outputs")
    parser.add_argument("-o", "--output", required=True, help="Output file for priority targets")
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    priority_urls = set()

    print("Collecting priority screenshot targets...")

    # 1. Admin login pages with Status: 200 (accessible)
    admin_file = input_dir / "Admin_Login_Enumerator_out.csv"
    if admin_file.exists():
        with open(admin_file, 'r') as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                if row.get('status') == 'Status: 200':
                    priority_urls.add(row['url'])
                    count += 1
            print(f"✓ Added {count} admin login pages (accessible)")

    # 2. Default/placeholder pages
    default_file = input_dir / "Default_Page_Checker_out.csv"
    if default_file.exists():
        with open(default_file, 'r') as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                if row.get('status') == '200' or 'default' in row.get('status', '').lower():
                    priority_urls.add(row['url'])
                    count += 1
            print(f"✓ Added {count} default/placeholder pages")

    # 3. Directory listings (unique URLs)
    dirlist_file = input_dir / "Dir_Listing_Checker_out.csv"
    if dirlist_file.exists():
        with open(dirlist_file, 'r') as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                url = row.get('Directory URL', '').strip()
                if url:
                    priority_urls.add(url)
                    count += 1
            # Count unique after adding all
            print(f"✓ Added {len(set([u for u in priority_urls if 'Directory' in str(dirlist_file)]))} unique directory listing URLs")

    # 4. Non-production/test/staging domains
    nonprod_file = input_dir / "Non_Production_domains_out.txt"
    if nonprod_file.exists():
        with open(nonprod_file, 'r') as f:
            count = 0
            for line in f:
                domain = line.strip()
                if domain:
                    # Add both HTTP and HTTPS versions
                    priority_urls.add(f"https://{domain}")
                    priority_urls.add(f"http://{domain}")
                    count += 1
            print(f"✓ Added {count} non-production domains")

    # Write output
    with open(args.output, 'w') as f:
        for url in sorted(priority_urls):
            f.write(url + '\n')

    print(f"\n✅ Generated {len(priority_urls)} priority screenshot targets")
    print(f"   Output: {args.output}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
