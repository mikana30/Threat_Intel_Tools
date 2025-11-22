#!/usr/bin/env python3
"""
Filter priority screenshot targets to reduce noise and focus on high-value targets.
"""
import csv
import sys
import argparse
from pathlib import Path
from urllib.parse import urlparse
from collections import defaultdict

def main():
    parser = argparse.ArgumentParser(
        description="Filter priority screenshot targets"
    )
    parser.add_argument("-i", "--input", required=True, help="Input priority targets file")
    parser.add_argument("-o", "--output", required=True, help="Filtered output file")
    parser.add_argument("--max-per-domain", type=int, default=3, help="Max URLs per domain (default: 3)")
    args = parser.parse_args()

    # High-value path priorities (lower number = higher priority)
    path_priority = {
        '/wp-admin': 1,
        '/admin': 2,
        '/login': 3,
        '/user/login': 4,
        '/dashboard': 5,
        '/administrator': 6,
        '/cpanel': 7,
        '/login.php': 8,
        '/admin.php': 9,
        '/admin/login': 10,
    }

    # High-value domain keywords (indicates test/staging/interesting environments)
    high_value_keywords = [
        '-qa', 'qa-', 'qa.',
        '-test', 'test-', 'test.',
        '-stg', 'stg-', 'staging',
        '-dev', 'dev-', 'dev.',
        '-uat', 'uat-',
        'admin', 'panel', 'portal'
    ]

    # Known platforms (these are more likely to have real admin interfaces)
    known_platforms = ['wp-admin', 'wp-login', 'user/login', 'drupal', 'joomla']

    urls_by_domain = defaultdict(list)

    # Read and categorize URLs
    with open(args.input, 'r') as f:
        for line in f:
            url = line.strip()
            if not url:
                continue

            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path.rstrip('/')

            # Calculate priority score
            score = 100

            # Path priority
            if path in path_priority:
                score = path_priority[path]

            # Boost score for high-value domains
            domain_lower = domain.lower()
            if any(keyword in domain_lower for keyword in high_value_keywords):
                score -= 50  # Lower score = higher priority

            # Boost for known platforms
            if any(platform in url.lower() for platform in known_platforms):
                score -= 30

            # Prefer HTTPS over HTTP
            if parsed.scheme == 'https':
                score -= 10

            urls_by_domain[domain].append((score, url, path))

    # Select top URLs per domain
    filtered_urls = set()
    high_priority_urls = []
    medium_priority_urls = []

    for domain, url_list in urls_by_domain.items():
        # Sort by priority score (lower = better)
        url_list.sort(key=lambda x: (x[0], x[2]))  # Sort by score, then path

        # Take top N per domain
        for score, url, path in url_list[:args.max_per_domain]:
            if score < 30:  # High priority (staging/test/known platforms)
                high_priority_urls.append((score, url))
            else:
                medium_priority_urls.append((score, url))

    # Sort by priority and combine
    high_priority_urls.sort(key=lambda x: x[0])
    medium_priority_urls.sort(key=lambda x: x[0])

    final_urls = [url for score, url in high_priority_urls] + [url for score, url in medium_priority_urls]

    # Write filtered output
    with open(args.output, 'w') as f:
        for url in final_urls:
            f.write(url + '\n')

    print(f"Original URLs: {sum(len(v) for v in urls_by_domain.values())}")
    print(f"Unique domains: {len(urls_by_domain)}")
    print(f"Filtered URLs: {len(final_urls)}")
    print(f"  High priority: {len(high_priority_urls)} (staging/test/known platforms)")
    print(f"  Medium priority: {len(medium_priority_urls)}")
    print(f"  Max per domain: {args.max_per_domain}")
    print(f"\nOutput written to: {args.output}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
