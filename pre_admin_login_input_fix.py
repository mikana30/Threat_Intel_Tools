#!/usr/bin/env python3
"""
Pre-stage guard for Admin_Login_Enumerator input.

Goal:
- Ensure 'clean_dnschecks.txt' is a newline-delimited list of valid domains,
  with no headers/commas/URLs.
- If the file is malformed or empty, rebuild it from
  'outputs/DNS_Records_Check_out.csv' (domain-like column).

This script ALWAYS exits 0 so the pipeline keeps moving.
"""

import argparse
import csv
import os
import re
from urllib.parse import urlparse

RESERVED = {"example.com","example.net","example.org","test.com","invalid","localdomain"}
RX_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)

def normalize_domain_or_url(s: str) -> str:
    s = (s or "").strip().strip(",;").lower()
    if not s:
        return ""
    # If likely a URL, extract hostname
    if "://" in s or s.startswith(("http:", "https:")):
        try:
            host = urlparse(s).netloc.split(":", 1)[0]
        except Exception:
            return ""
        if host.startswith("www."):
            host = host[4:]
        return host if RX_DOMAIN.match(host) else ""
    # Bare domain?
    if s.startswith("www."):
        s = s[4:]
    return s if RX_DOMAIN.match(s) else ""

def read_lines(path: str) -> list[str]:
    vals = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    vals.append(line)
    except FileNotFoundError:
        pass
    return vals

def looks_malformed(lines: list[str]) -> bool:
    if not lines:
        return True
    head = lines[0].lower()
    if "," in head or head.startswith("domain,") or head.startswith("url,"):
        return True
    # Also consider malformed if many lines have commas/spaces
    badish = sum(1 for x in lines[:50] if ("," in x or " " in x))
    return badish > 0

def extract_domains_from_csv(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    domains = []
    with open(path, "r", newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return []
        # pick best column: domain > host > hostname > url > name
        cols_lower = [c.lower() for c in reader.fieldnames if c]
        pick = None
        for want in ("domain", "host", "hostname", "url", "name"):
            if want in cols_lower:
                # map to real-case fieldname
                pick = next(real for real in reader.fieldnames if real.lower() == want)
                break
        if not pick:
            return []
        for row in reader:
            val = normalize_domain_or_url(row.get(pick, ""))
            if val and val not in RESERVED:
                domains.append(val)
    # de-dup + sort
    return sorted(set(domains))

def write_dst(domains: list[str], dst: str) -> None:
    with open(dst, "w", encoding="utf-8") as out:
        out.write("\n".join(sorted(set(domains))))
        if domains:
            out.write("\n")

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize clean_dnschecks input for Admin_Login_Enumerator.")
    parser.add_argument("--dst", default="clean_dnschecks.txt", help="Target domain list (default: clean_dnschecks.txt)")
    parser.add_argument("--src", default="outputs/DNS_Records_Check_out.csv", help="CSV fallback (default: outputs/DNS_Records_Check_out.csv)")
    return parser.parse_args()


def main():
    args = parse_args()
    dst = args.dst
    src = args.src

    current = read_lines(dst)
    if not looks_malformed(current):
        # Already good: validate quickly and rewrite cleanly (idempotent)
        cleaned = []
        for s in current:
            d = normalize_domain_or_url(s)
            if d and d not in RESERVED:
                cleaned.append(d)
        write_dst(cleaned, dst)
        print(f"[OK] {dst} validated ({len(cleaned)} domains).")
        return

    # Try to rebuild from CSV source
    rebuilt = extract_domains_from_csv(src)
    if rebuilt:
        write_dst(rebuilt, dst)
        print(f"[FIX] Rebuilt {dst} from {src} ({len(rebuilt)} domains).")
        return

    # Fallback: salvage what we can from current file (even if malformed)
    salvaged = []
    for s in current:
        d = normalize_domain_or_url(s)
        if d and d not in RESERVED:
            salvaged.append(d)
    write_dst(salvaged, dst)
    print(f"[WARN] {dst} malformed/empty and {src} missing or unusable; "
          f"wrote {len(salvaged)} salvaged domains.")
    # Always exit 0

if __name__ == "__main__":
    main()
