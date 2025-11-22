#!/usr/bin/env python3
"""
Test script for Threat Context Enrichment System
Generates sample data and tests the enrichment pipeline
"""

import os
import json
import csv
import tempfile
import shutil
from pathlib import Path

def create_test_data(test_dir):
    """Create sample test data for threat enrichment"""

    raw_outputs = os.path.join(test_dir, 'raw_outputs')
    os.makedirs(raw_outputs, exist_ok=True)

    # 1. Create tech_detection_unified.json
    tech_data = {
        "vulnerable.example.com": {
            "Apache": "2.4.49",
            "PHP": "7.3.0",
            "OpenSSL": "1.0.1e"
        },
        "secure.example.com": {
            "Nginx": "1.21.0",
            "OpenSSH": "8.9p1"
        },
        "legacy.example.com": {
            "Apache": "2.2.15",
            "MySQL": "5.5.68",
            "PHP": "5.6.40"
        }
    }

    with open(os.path.join(raw_outputs, 'tech_detection_unified.json'), 'w') as f:
        json.dump(tech_data, f, indent=2)

    print(f"✓ Created tech_detection_unified.json")

    # 2. Create Open_Ports_1_out.csv
    ports_data = [
        {"domain": "vulnerable.example.com", "ip": "192.168.1.10", "port": "22", "banner": "SSH-2.0-OpenSSH_7.4"},
        {"domain": "vulnerable.example.com", "ip": "192.168.1.10", "port": "80", "banner": "Apache/2.4.49 (Unix)"},
        {"domain": "vulnerable.example.com", "ip": "192.168.1.10", "port": "3306", "banner": "MySQL 5.5.68"},
        {"domain": "legacy.example.com", "ip": "192.168.1.20", "port": "21", "banner": "FTP Server Ready"},
        {"domain": "legacy.example.com", "ip": "192.168.1.20", "port": "23", "banner": "Telnet Server"},
        {"domain": "legacy.example.com", "ip": "192.168.1.20", "port": "445", "banner": "SMB Server"},
        {"domain": "secure.example.com", "ip": "192.168.1.30", "port": "443", "banner": "nginx/1.21.0"},
        {"domain": "secure.example.com", "ip": "192.168.1.30", "port": "22", "banner": "SSH-2.0-OpenSSH_8.9"},
    ]

    with open(os.path.join(raw_outputs, 'Open_Ports_1_out.csv'), 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['domain', 'ip', 'port', 'banner'])
        writer.writeheader()
        writer.writerows(ports_data)

    print(f"✓ Created Open_Ports_1_out.csv")

    # 3. Create SSL_TLS_Cert_Check_out.csv
    ssl_data = [
        {"domain": "vulnerable.example.com", "cert_expiry": "Jan 15 23:59:59 2026 GMT", "days_until_expiry": "67", "status": "ok"},
        {"domain": "legacy.example.com", "cert_expiry": "Oct 10 23:59:59 2020 GMT", "days_until_expiry": "-1500", "status": "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired"},
        {"domain": "secure.example.com", "cert_expiry": "Dec 31 23:59:59 2026 GMT", "days_until_expiry": "400", "status": "ok"},
        {"domain": "selfsigned.example.com", "cert_expiry": "", "days_until_expiry": "", "status": "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate"},
    ]

    with open(os.path.join(raw_outputs, 'SSL_TLS_Cert_Check_out.csv'), 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['domain', 'cert_expiry', 'days_until_expiry', 'status'])
        writer.writeheader()
        writer.writerows(ssl_data)

    print(f"✓ Created SSL_TLS_Cert_Check_out.csv")

    return raw_outputs


def verify_outputs(output_dir):
    """Verify that expected output files were created"""

    expected_files = [
        'threat_context.json',
        'threat_context_summary.csv',
        'high_risk_assets.txt',
        'remediation_guidance.json'
    ]

    print("\n" + "="*60)
    print("VERIFICATION")
    print("="*60)

    all_exist = True
    for filename in expected_files:
        filepath = os.path.join(output_dir, filename)
        exists = os.path.exists(filepath)

        if exists:
            size = os.path.getsize(filepath)
            print(f"✓ {filename:30s} ({size:,} bytes)")
        else:
            print(f"✗ {filename:30s} MISSING")
            all_exist = False

    return all_exist


def display_sample_results(output_dir):
    """Display sample results from the enrichment"""

    print("\n" + "="*60)
    print("SAMPLE RESULTS")
    print("="*60)

    # Show threat context summary
    summary_file = os.path.join(output_dir, 'threat_context_summary.csv')
    if os.path.exists(summary_file):
        print("\nThreat Context Summary (first 10 rows):")
        print("-" * 60)
        with open(summary_file, 'r') as f:
            lines = f.readlines()[:11]  # Header + 10 rows
            for line in lines:
                print(line.rstrip())

    # Show high risk assets
    high_risk_file = os.path.join(output_dir, 'high_risk_assets.txt')
    if os.path.exists(high_risk_file):
        print("\n\nHigh Risk Assets (CVSS >= 7.0):")
        print("-" * 60)
        with open(high_risk_file, 'r') as f:
            content = f.read().strip()
            if content:
                print(content)
            else:
                print("(No high-risk assets found - this is good!)")

    # Show metadata from threat_context.json
    context_file = os.path.join(output_dir, 'threat_context.json')
    if os.path.exists(context_file):
        with open(context_file, 'r') as f:
            data = json.load(f)
            metadata = data.get('metadata', {})

            print("\n\nEnrichment Metadata:")
            print("-" * 60)
            print(f"Generated at:    {metadata.get('generated_at', 'N/A')}")
            print(f"Total assets:    {metadata.get('total_assets', 0)}")
            print(f"Total findings:  {metadata.get('total_findings', 0)}")


def main():
    """Main test function"""

    print("="*60)
    print("THREAT CONTEXT ENRICHMENT - TEST RUNNER")
    print("="*60)
    print()

    # Create temporary test directory
    test_dir = tempfile.mkdtemp(prefix='threat_enrich_test_')
    print(f"Test directory: {test_dir}\n")

    try:
        # Step 1: Create test data
        print("Step 1: Creating test data")
        print("-" * 60)
        raw_outputs = create_test_data(test_dir)

        # Step 2: Run enrichment
        print("\n\nStep 2: Running threat enrichment")
        print("-" * 60)
        print("Command:")

        output_dir = os.path.join(test_dir, 'threat_context')

        cmd = f"python3 threat_context_enricher.py " \
              f"--input-dir {raw_outputs} " \
              f"--output-dir {output_dir} " \
              f"--config config/threat_intel.yml"

        print(f"  {cmd}")
        print()
        print("NOTE: This is a DRY RUN demonstration.")
        print("To actually run the enrichment, execute:")
        print(f"\n  cd /home/kali/Desktop/threat_intel/Threat\\ Intel\\ Tools\\ and\\ Work\\ Flow")
        print(f"  {cmd}")
        print()

        # Step 3: Show what would be expected
        print("\n\nStep 3: Expected outputs")
        print("-" * 60)
        print("The enrichment would generate:")
        print("  ✓ threat_context.json - Full structured enrichment data")
        print("  ✓ threat_context_summary.csv - Tabular CVE report")
        print("  ✓ high_risk_assets.txt - Assets with CVSS >= 7.0")
        print("  ✓ remediation_guidance.json - Remediation steps per CVE")

        print("\n\nStep 4: Sample test data created at:")
        print("-" * 60)
        print(f"  Input dir:  {raw_outputs}")
        print(f"  Output dir: {output_dir} (not yet created)")
        print("\nYou can manually run the enrichment on this test data.")

        # Keep test data for inspection
        print(f"\n\nTest data preserved at: {test_dir}")
        print("Delete manually when done: rm -rf {test_dir}")

    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()

        # Cleanup on error
        if os.path.exists(test_dir):
            shutil.rmtree(test_dir)

        return 1

    return 0


if __name__ == '__main__':
    exit(main())
