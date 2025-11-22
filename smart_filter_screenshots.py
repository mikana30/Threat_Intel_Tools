#!/usr/bin/env python3
"""
Smart filter for priority screenshots - removes noise while keeping valuable findings.

Strategy:
1. Domains with 1-2 hits: KEEP ALL (likely real admin panels)
2. Domains with 3-9 hits: KEEP TOP 2 (some real, some catch-all behavior)
3. Domains with 10+ hits: KEEP TOP 1 (catch-all, but might have real wp-admin)
4. Prioritize: staging/qa/test > known platforms > common paths
"""
import csv
import sys
import argparse
from pathlib import Path
from urllib.parse import urlparse
from collections import defaultdict

def score_url(url, domain_lower):
    """Score URL by likelihood of being a real admin panel (lower = better)"""
    score = 100

    # High-value environments (staging/qa/test are often less protected)
    high_value_env = ['-qa', 'qa-', 'qa.', '-test', 'test-', 'test.',
                      '-stg', 'stg-', 'staging', '-dev', 'dev-', 'dev.', '-uat', 'uat-']
    if any(kw in domain_lower for kw in high_value_env):
        score -= 50

    # Known real platforms (these are actual admin interfaces)
    real_platforms = {
        '/wp-admin': -40,      # WordPress admin (very common, very real)
        '/wp-login': -40,
        '/user/login': -35,    # Drupal login (real)
        '/admin': -25,         # Generic but common
        '/login': -20,
        '/cpanel': -30,        # cPanel (real)
        '/phpmyadmin': -40,    # Database admin (real but risky)
    }

    url_lower = url.lower()
    for platform, value in real_platforms.items():
        if platform in url_lower:
            score += value
            break

    # HTTPS preferred
    if url.startswith('https://'):
        score -= 10

    # Deprioritize generic/unlikely paths
    unlikely = ['/admin.php', '/login.php', '/adminpanel', '/admin_area',
                '/admin_console', '/backend', '/moderator', '/manage']
    if any(path in url_lower for path in unlikely):
        score += 30

    return score

def main():
    parser = argparse.ArgumentParser(
        description="Smart filter for screenshot targets - removes noise, keeps value"
    )
    parser.add_argument("-i", "--input-dir", required=True, help="Directory containing scan outputs")
    parser.add_argument("-o", "--output", required=True, help="Filtered output file")
    parser.add_argument("--include-non-prod", action="store_true",
                       help="Include non-production domains from separate file")
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    admin_file = input_dir / "Admin_Login_Enumerator_out.csv"

    if not admin_file.exists():
        print(f"ERROR: {admin_file} not found")
        return 1

    # Organize URLs by domain
    urls_by_domain = defaultdict(list)

    with open(admin_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get('status') == 'Status: 200':
                url = row['url']
                domain = row['domain']
                domain_lower = domain.lower()

                score = score_url(url, domain_lower)
                urls_by_domain[domain].append((score, url))

    # Apply smart filtering rules
    filtered_urls = []
    stats = {
        'catch_all': 0,
        'medium': 0,
        'precise': 0,
        'total_urls': 0
    }

    for domain, url_list in urls_by_domain.items():
        hit_count = len(url_list)
        stats['total_urls'] += hit_count

        # Sort by score (lower = better)
        url_list.sort(key=lambda x: x[0])

        # Apply filtering rules
        if hit_count <= 2:
            # 1-2 hits: Keep all (very likely real)
            keep = url_list
            stats['precise'] += 1
        elif hit_count <= 9:
            # 3-9 hits: Keep top 2 (some signal, some noise)
            keep = url_list[:2]
            stats['medium'] += 1
        else:
            # 10+ hits: Keep only top 1 (mostly noise, but keep best)
            keep = url_list[:1]
            stats['catch_all'] += 1

        filtered_urls.extend([url for score, url in keep])

    # Sort final list: high-value environments first, then by URL
    def sort_key(url):
        domain_lower = urlparse(url).netloc.lower()
        is_high_value = any(kw in domain_lower for kw in
                          ['-qa', 'qa-', 'qa.', '-test', 'test-', 'test.',
                           '-stg', 'stg-', 'staging', '-dev', 'dev-'])
        return (0 if is_high_value else 1, url)

    filtered_urls.sort(key=sort_key)

    # Optionally add non-production domains
    if args.include_non_prod:
        nonprod_file = input_dir / "Non_Production_domains_out.txt"
        if nonprod_file.exists():
            with open(nonprod_file, 'r') as f:
                for line in f:
                    domain = line.strip()
                    if domain:
                        # Add HTTPS version only (preferred)
                        filtered_urls.append(f"https://{domain}")

    # Write output
    with open(args.output, 'w') as f:
        for url in filtered_urls:
            f.write(url + '\n')

    # Print statistics
    print("\n" + "="*60)
    print("SMART SCREENSHOT FILTER RESULTS")
    print("="*60)
    print(f"\nInput Analysis:")
    print(f"  Total domains: {len(urls_by_domain)}")
    print(f"  Total URLs (Status 200): {stats['total_urls']}")
    print(f"\nDomain Categories:")
    print(f"  Precise hits (1-2 URLs):  {stats['precise']:3d} domains → kept ALL")
    print(f"  Medium hits (3-9 URLs):   {stats['medium']:3d} domains → kept TOP 2")
    print(f"  Catch-all (10+ URLs):     {stats['catch_all']:3d} domains → kept TOP 1")
    print(f"\nOutput:")
    print(f"  Filtered URLs: {len(filtered_urls)}")
    print(f"  Reduction: {stats['total_urls']} → {len(filtered_urls)} " +
          f"({100*(1-len(filtered_urls)/stats['total_urls']):.1f}% reduction)")
    print(f"\n  Output file: {args.output}")
    print("="*60 + "\n")

    return 0

if __name__ == "__main__":
    sys.exit(main())
