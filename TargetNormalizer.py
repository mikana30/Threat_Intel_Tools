#!/usr/bin/env python3
"""
Target Normalizer
-----------------
Reads a plain text targets file and writes a normalized JSON list with metadata.
Extracts apex/registered domains for proper subdomain enumeration.
"""

import argparse
import json
import logging
from pathlib import Path

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

from dev_mode import get_target_cap, load_env_settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def extract_apex_domain(domain: str) -> str:
    """
    Extract the apex/registered domain for recon.

    Examples:
        www6.slac.stanford.edu -> slac.stanford.edu
        mail.google.com -> google.com
        example.com -> example.com
        www.bbc.co.uk -> bbc.co.uk
        localhost -> localhost (preserved)
        192.168.1.1 -> 192.168.1.1 (preserved)
    """
    # Handle localhost and IP addresses - return as-is
    if not '.' in domain or domain.replace('.', '').replace(':', '').isdigit():
        return domain

    if HAS_TLDEXTRACT:
        ext = tldextract.extract(domain)

        # If no valid extraction, return original
        if not ext.registered_domain:
            return domain

        # For .edu domains with organizational subdomain, keep one level
        # www6.slac.stanford.edu -> slac.stanford.edu
        # portal.cs.mit.edu -> cs.mit.edu
        if ext.suffix == 'edu' and ext.subdomain:
            subdomain_parts = ext.subdomain.split('.')
            if len(subdomain_parts) >= 2:
                # Has org subdomain like "slac" in "www6.slac"
                last_sub = subdomain_parts[-1]
                return f"{last_sub}.{ext.registered_domain}"

        # For .ac.uk and similar multi-level academic TLDs
        # webmail.staff.university.ac.uk -> staff.university.ac.uk
        if ext.suffix in ('ac.uk', 'edu.au', 'ac.jp', 'edu.cn') and ext.subdomain:
            subdomain_parts = ext.subdomain.split('.')
            if len(subdomain_parts) >= 2:
                # Keep organizational subdomain
                last_sub = subdomain_parts[-1]
                return f"{last_sub}.{ext.registered_domain}"

        # For all other cases, return the registered domain
        # mail.google.com -> google.com
        # www.bbc.co.uk -> bbc.co.uk
        return ext.registered_domain
    else:
        # Fallback: simple heuristic without tldextract
        parts = domain.split('.')
        if len(parts) == 4 and parts[-1] == 'edu':
            # slac.stanford.edu case
            return '.'.join(parts[-3:])
        elif len(parts) > 2:
            # Default to last 2 parts
            return '.'.join(parts[-2:])
        return domain


def main():
    parser = argparse.ArgumentParser(
        description="Normalize targets into JSON with automatic apex domain extraction"
    )
    parser.add_argument("--input", required=True, help="targets.txt file")
    parser.add_argument("--output", required=True, help="Output JSON path")
    parser.add_argument("--tag", action="append", help="Optional tag to attach")
    parser.add_argument(
        "--no-extract",
        action="store_true",
        help="Disable automatic apex domain extraction (use domains as-is)",
    )
    parser.add_argument(
        "--env-config",
        default="config/environment.yml",
        help="Optional environment config that may enable dev caps",
    )
    args = parser.parse_args()

    target_file = Path(args.input)
    output_file = Path(args.output)
    env_settings = load_env_settings(Path(args.env_config))
    cap = get_target_cap(env_settings)

    targets = []
    for line in target_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        original_domain = line.lower()

        # Allow user to disable extraction with --no-extract flag
        if args.no_extract:
            apex_domain = original_domain
        else:
            apex_domain = extract_apex_domain(original_domain)

        targets.append(
            {
                "domain": apex_domain,
                "original_input": original_domain,
                "tags": args.tag or [],
            }
        )

        if apex_domain != original_domain:
            logging.info(
                "Extracted apex domain: %s -> %s", original_domain, apex_domain
            )

    if cap:
        original_count = len(targets)
        targets = targets[:cap]
        logging.info(
            "Dev target cap active (%d) - truncated targets from %d to %d",
            cap,
            original_count,
            len(targets),
        )

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(targets, indent=2))
    logging.info("Wrote %d normalized targets to %s", len(targets), output_file)


if __name__ == "__main__":
    main()
