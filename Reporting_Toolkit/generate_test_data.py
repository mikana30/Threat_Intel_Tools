#!/usr/bin/env python3
"""
Test Data Generator for Reporting Toolkit
Generates sample CSV files for all report sections to test report generation
"""

import csv
import os
import random
from datetime import datetime, timedelta
from pathlib import Path

# Configuration
TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), 'test_data')

# Sample data pools
SUBDOMAINS = [
    'www', 'api', 'staging', 'mail', 'vpn', 'admin', 'dev', 'test',
    'cdn', 'static', 'blog', 'shop', 'auth', 'dashboard', 'monitor',
    'portal', 'backup', 'db', 'cache', 'storage', 'files'
]

DOMAINS = [
    'example.com', 'acmecorp.com', 'techventures.io', 'globalservices.net',
    'securedata.org', 'innovatorslab.dev', 'cloudpartners.com'
]

TECHNOLOGIES = {
    'Apache': ['2.4.41', '2.4.52', '2.4.58'],
    'Nginx': ['1.18.0', '1.20.0', '1.24.0'],
    'PHP': ['7.4.3', '8.0.1', '8.1.0', '8.2.0'],
    'WordPress': ['5.8.0', '6.0.0', '6.1.0', '6.2.0'],
    'jQuery': ['1.8.3', '2.1.0', '3.5.1', '3.6.0', '3.7.0'],
    'React': ['16.8.0', '17.0.0', '18.0.0', '18.2.0'],
    'Bootstrap': ['3.3.7', '4.6.0', '5.0.0', '5.3.0']
}

HTTP_STATUS_CODES = [200, 301, 302, 400, 403, 404, 500, 503]

CLOUD_PROVIDERS = ['AWS S3', 'Azure Blob Storage', 'GCP Cloud Storage']

RISK_LEVELS = ['High', 'Medium', 'Low']
CLOUD_RISK_LEVELS = ['Extreme', 'High', 'Medium', 'Low', 'Informational']

ADMIN_PATHS = [
    '/admin', '/login', '/wp-admin', '/administrator', '/control-panel',
    '/cpanel', '/phpmyadmin', '/admin.php', '/admin.asp', '/admin.aspx',
    '/management', '/console', '/api/admin', '/backend', '/internal'
]

BUCKET_NAMES = [
    'company-backups-2024', 'internal-documents', 'customer-data-prod',
    'temp-uploads', 'old-archives', 'development-builds', 'raw-logs',
    'media-assets', 'config-files', 'snapshots', 'test-bucket-1'
]

CERT_ISSUERS = [
    'DigiCert Global CA G2', 'Let\'s Encrypt Authority X3', 'GlobalSign Domain Validation CA',
    'Sectigo RSA Domain Validation Secure Server CA', 'Amazon Root CA 4',
    'GeoTrust Universal CA 2'
]

VNC_PORTS = [5900, 5901, 5902, 5903]

def generate_random_date(days_ago_min=0, days_ago_max=365):
    """Generate a random date within the specified range"""
    days_ago = random.randint(days_ago_min, days_ago_max)
    return (datetime.now() - timedelta(days=days_ago)).strftime('%Y-%m-%d')

def generate_random_ip():
    """Generate a random IP address"""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

def generate_random_cidr():
    """Generate a random CIDR block"""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.0.0/16"

def generate_recon_out_enriched():
    """Generate Recon_out_enriched.csv (50 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'Recon_out_enriched.csv')
    rows = []

    for i in range(50):
        domain = f"{random.choice(SUBDOMAINS)}.{random.choice(DOMAINS)}"
        ip = generate_random_ip()
        http_status = random.choice(HTTP_STATUS_CODES)
        http_title = random.choice([
            'Welcome to Apache2 Ubuntu Default Page',
            'Nginx Welcome Page',
            'Internal Server',
            'Dashboard Login',
            'Application Server',
            'Static Content Server',
            '404 Not Found'
        ])
        sources = random.choice(['sublist3r', 'crt.sh', 'common-crawl', 'dnsenum', 'amass'])
        whois_org = random.choice([
            'Acme Corporation',
            'TechVentures Inc',
            'Global Services Ltd',
            'CloudPartners LLC',
            'SecureData Systems'
        ])
        whois_cidr = generate_random_cidr()

        rows.append({
            'domain': domain,
            'ip': ip,
            'http_status': http_status,
            'http_title': http_title,
            'sources': sources,
            'whois_org': whois_org,
            'whois_cidr': whois_cidr
        })

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['domain', 'ip', 'http_status', 'http_title', 'sources', 'whois_org', 'whois_cidr'])
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def generate_tech_detection_unified():
    """Generate tech_detection_unified.csv (30 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'tech_detection_unified.csv')
    rows = []

    urls = [f"https://{random.choice(SUBDOMAINS)}.{random.choice(DOMAINS)}" for _ in range(30)]

    for url in urls:
        row = {'url': url}

        # Randomly assign technologies
        if random.random() > 0.3:
            row['Apache'] = f"Apache/{random.choice(TECHNOLOGIES['Apache'])}"
        if random.random() > 0.4:
            row['Nginx'] = f"Nginx/{random.choice(TECHNOLOGIES['Nginx'])}"
        if random.random() > 0.4:
            row['PHP'] = f"PHP/{random.choice(TECHNOLOGIES['PHP'])}"
        if random.random() > 0.5:
            row['WordPress'] = f"WordPress/{random.choice(TECHNOLOGIES['WordPress'])}"
        if random.random() > 0.2:
            row['jQuery'] = f"jQuery/{random.choice(TECHNOLOGIES['jQuery'])}"
        if random.random() > 0.5:
            row['React'] = f"React/{random.choice(TECHNOLOGIES['React'])}"
        if random.random() > 0.6:
            row['Bootstrap'] = f"Bootstrap/{random.choice(TECHNOLOGIES['Bootstrap'])}"

        rows.append(row)

    fieldnames = ['url', 'Apache', 'Nginx', 'PHP', 'WordPress', 'jQuery', 'React', 'Bootstrap']

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    return len(rows)

def generate_crt_transparency():
    """Generate crt_transparency.csv (25 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'crt_transparency.csv')
    rows = []

    for i in range(25):
        domain = f"{random.choice(SUBDOMAINS)}.{random.choice(DOMAINS)}"
        common_name = domain
        name_value = f"*.{random.choice(DOMAINS)}"
        issuer = random.choice(CERT_ISSUERS)
        not_before = generate_random_date(days_ago_min=30, days_ago_max=365)
        not_after = (datetime.now() + timedelta(days=random.randint(30, 365))).strftime('%Y-%m-%d')

        rows.append({
            'domain': domain,
            'common_name': common_name,
            'name_value': name_value,
            'issuer_name': issuer,
            'not_before': not_before,
            'not_after': not_after
        })

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['domain', 'common_name', 'name_value', 'issuer_name', 'not_before', 'not_after'])
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def generate_other_buckets():
    """Generate Other_Buckets_out.csv (15 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'Other_Buckets_out.csv')
    rows = []

    for i in range(15):
        bucket_name = f"{random.choice(BUCKET_NAMES)}-{random.randint(1000, 9999)}"
        provider = random.choice(CLOUD_PROVIDERS)
        status = random.choice(['Accessible', 'Restricted', 'Not Found', 'Error'])
        risk = random.choice(CLOUD_RISK_LEVELS)
        sample_files = random.choice([
            'config.json, secrets.env, backup.sql',
            'README.md, .git/config, keys.txt',
            'database_dump.tar.gz, private_keys.pem',
            'credentials.json, api_keys.yaml',
            'no_sensitive_files_found'
        ])

        # Construct URL based on provider
        if 'AWS' in provider:
            url = f"s3.amazonaws.com/{bucket_name}"
        elif 'Azure' in provider:
            url = f"{bucket_name}.blob.core.windows.net"
        else:
            url = f"storage.googleapis.com/{bucket_name}"

        rows.append({
            'bucket_name': bucket_name,
            'provider': provider,
            'status': status,
            'risk': risk,
            'sample_files': sample_files,
            'url': url
        })

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['bucket_name', 'provider', 'status', 'risk', 'sample_files', 'url'])
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def generate_admin_login_enumerator():
    """Generate Admin_Login_Enumerator_out.csv (10 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'Admin_Login_Enumerator_out.csv')
    rows = []

    for i in range(10):
        domain = f"{random.choice(SUBDOMAINS)}.{random.choice(DOMAINS)}"
        url = f"https://{domain}{random.choice(ADMIN_PATHS)}"
        status = random.choice(['Status: 200', 'Status: 403', 'Status: 404'])

        rows.append({
            'domain': domain,
            'url': url,
            'status': status
        })

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['domain', 'url', 'status'])
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def generate_git_leak():
    """Generate Git_Leak_out.csv (5 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'Git_Leak_out.csv')
    rows = []

    for i in range(5):
        domain = f"{random.choice(SUBDOMAINS)}.{random.choice(DOMAINS)}"
        leak_url = f"https://{domain}/.git/"
        status_code = random.choice(['200', '403', '301'])
        risk = random.choice(['High', 'Medium', 'Low'])

        rows.append({
            'domain': domain,
            'leak_url': leak_url,
            'status_code': status_code,
            'Risk': risk
        })

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['domain', 'leak_url', 'status_code', 'Risk'])
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def generate_s3_bucket_check():
    """Generate S3_Bucket_Check_out.csv (8 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'S3_Bucket_Check_out.csv')
    rows = []

    for i in range(8):
        bucket_name = f"bucket-{random.randint(10000, 99999)}"
        region = random.choice(['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'])
        status = random.choice(['Accessible', 'Private', 'Not Found', 'Error', 'Restricted'])
        risk = random.choice(['High', 'Medium', 'Low'])

        rows.append({
            'bucket_name': bucket_name,
            'region': region,
            'status': status,
            'Risk': risk
        })

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['bucket_name', 'region', 'status', 'Risk'])
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def generate_vnc_checker():
    """Generate VNC_Checker_out.csv (3 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'VNC_Checker_out.csv')
    rows = []

    for i in range(3):
        ip = generate_random_ip()
        port = random.choice(VNC_PORTS)
        status = random.choice(['Open', 'Accessible', 'Protected'])

        rows.append({
            'ip': ip,
            'port': port,
            'status': status
        })

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['ip', 'port', 'status'])
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def generate_email_security_audit():
    """Generate Email_Security_Audit_out.csv (5 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'Email_Security_Audit_out.csv')
    rows = []

    for i in range(5):
        domain = random.choice(DOMAINS)
        spf_status = random.choice(['Valid', 'Invalid', 'Missing', 'Weak'])
        dmarc_status = random.choice(['Enforced', 'Quarantine', 'None', 'Missing'])
        risk = random.choice(['High', 'Medium', 'Low'])

        rows.append({
            'domain': domain,
            'spf_status': spf_status,
            'dmarc_status': dmarc_status,
            'Risk': risk
        })

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['domain', 'spf_status', 'dmarc_status', 'Risk'])
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def generate_ssl_tls_cert_check():
    """Generate SSL_TLS_Cert_Check_out.csv (6 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'SSL_TLS_Cert_Check_out.csv')
    rows = []

    for i in range(6):
        domain = f"{random.choice(SUBDOMAINS)}.{random.choice(DOMAINS)}"
        cert_expiry = (datetime.now() + timedelta(days=random.randint(-30, 90))).strftime('%Y-%m-%d')
        days_until_expiry = random.randint(-30, 90)
        risk = random.choice(['Critical', 'High', 'Medium', 'Low'])

        rows.append({
            'domain': domain,
            'cert_expiry': cert_expiry,
            'days_until_expiry': days_until_expiry,
            'Risk': risk
        })

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['domain', 'cert_expiry', 'days_until_expiry', 'Risk'])
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def generate_waf_checker():
    """Generate WAF_Checker_out.csv (5 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'WAF_Checker_out.csv')
    rows = []

    for i in range(5):
        domain = f"{random.choice(SUBDOMAINS)}.{random.choice(DOMAINS)}"
        waf_detected = random.choice(['true', 'false'])
        waf_headers = random.choice(['Cloudflare', 'AWS WAF', 'Akamai', 'Not detected', 'error'])
        risk = random.choice(['High', 'Medium', 'Low'])

        rows.append({
            'domain': domain,
            'waf_detected': waf_detected,
            'waf_headers': waf_headers,
            'Risk': risk
        })

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['domain', 'waf_detected', 'waf_headers', 'Risk'])
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def generate_subdomain_takeover_checker():
    """Generate Subdomain_Takeover_Checker_out.csv (4 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'Subdomain_Takeover_Checker_out.csv')
    rows = []

    for i in range(4):
        domain = f"{random.choice(SUBDOMAINS)}.{random.choice(DOMAINS)}"
        target = random.choice(['github.io', 'herokuapp.com', 'azure.com', 'vercel.app'])
        takeover_status = random.choice(['vulnerable', 'safe', 'edge_case'])
        ssl_expiry = (datetime.now() + timedelta(days=random.randint(-30, 90))).strftime('%Y-%m-%d')

        rows.append({
            'domain': domain,
            'target': target,
            'takeover_status': takeover_status,
            'ssl_expiry': ssl_expiry
        })

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['domain', 'target', 'takeover_status', 'ssl_expiry'])
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def generate_debug_paths():
    """Generate Debug_paths_out.csv (4 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'Debug_paths_out.csv')
    rows = []

    debug_paths = [
        '/debug', '/test', '/console', '/.well-known/debug',
        '/api/debug', '/admin/debug', '/dev/test', '/internal/status'
    ]

    for i in range(4):
        domain = f"{random.choice(SUBDOMAINS)}.{random.choice(DOMAINS)}"
        path = random.choice(debug_paths)
        url = f"https://{domain}{path}"
        status = random.choice(['(200)', '(403)', '(404)'])

        rows.append({
            'domain': domain,
            'path': path,
            'url': url,
            'status': status
        })

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['domain', 'path', 'url', 'status'])
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def generate_default_page_checker():
    """Generate Default_Page_Checker_out.csv (3 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'Default_Page_Checker_out.csv')
    rows = []

    default_pages = [
        'It works!',
        'Welcome to nginx!',
        'Apache2 Ubuntu Default Page',
        'Server Ready'
    ]

    for i in range(3):
        domain = f"{random.choice(SUBDOMAINS)}.{random.choice(DOMAINS)}"
        url = f"https://{domain}"
        status = random.choice(['200', '403', '404'])
        server = random.choice(['Apache', 'Nginx', 'IIS', 'LiteSpeed'])
        title = random.choice(default_pages)

        rows.append({
            'url': url,
            'status': status,
            'server': server,
            'title': title
        })

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['url', 'status', 'server', 'title'])
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def generate_dir_listing_checker():
    """Generate Dir_Listing_Checker_out.csv (4 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'Dir_Listing_Checker_out.csv')
    rows = []

    for i in range(4):
        domain = f"{random.choice(SUBDOMAINS)}.{random.choice(DOMAINS)}"
        directory_url = f"https://{domain}/uploads/"
        file_url = f"https://{domain}/uploads/backup.zip"
        file_name = random.choice(['backup.zip', 'config.txt', 'database.sql', 'keys.pem'])
        size = f"{random.randint(1, 100)}MB"
        last_modified = generate_random_date()

        rows.append({
            'Directory URL': directory_url,
            'File URL': file_url,
            'File Name': file_name,
            'Size': size,
            'Last Modified': last_modified
        })

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['Directory URL', 'File URL', 'File Name', 'Size', 'Last Modified'])
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def generate_dead_dns_checker():
    """Generate Dead_DNS_Checker_out.csv (3 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'Dead_DNS_Checker_out.csv')
    rows = []

    for i in range(3):
        domain = f"{random.choice(SUBDOMAINS)}.{random.choice(DOMAINS)}"
        stale = random.choice(['true', 'false'])
        record_type = random.choice(['CNAME', 'A', 'MX', 'NS'])
        target = random.choice([
            'old-service.herokuapp.com',
            'github.io',
            'defunct.example.com',
            generate_random_ip()
        ])

        rows.append({
            'domain': domain,
            'stale': stale,
            'type': record_type,
            'target': target
        })

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['domain', 'stale', 'type', 'target'])
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def generate_dead_dns_resolver():
    """Generate Dead_DNS_Resolver_out.csv (3 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'Dead_DNS_Resolver_out.csv')
    rows = []

    for i in range(3):
        domain = f"{random.choice(SUBDOMAINS)}.{random.choice(DOMAINS)}"
        target = random.choice([
            'github.io',
            'herokuapp.com',
            'vercel.app',
            'azure.com'
        ])
        takeover_status = random.choice(['vulnerable', 'safe'])
        ssl_expiry = (datetime.now() + timedelta(days=random.randint(-30, 90))).strftime('%Y-%m-%d')

        rows.append({
            'domain': domain,
            'target': target,
            'takeover_status': takeover_status,
            'ssl_expiry': ssl_expiry
        })

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['domain', 'target', 'takeover_status', 'ssl_expiry'])
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def generate_detect_internal_dns():
    """Generate Detect_Internal_DNS_out.csv (4 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'Detect_Internal_DNS_out.csv')
    rows = []

    internal_ips = [
        '10.0.1.15',
        '192.168.1.100',
        '172.16.0.50',
        '10.255.255.1'
    ]

    for i in range(4):
        finding = f"Internal IP {random.choice(internal_ips)} found in HTML response"
        source = f"https://{random.choice(SUBDOMAINS)}.{random.choice(DOMAINS)}"

        rows.append({
            'Finding': finding,
            'Source': source
        })

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['Finding', 'Source'])
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def generate_non_production_domains():
    """Generate Non_Production_domains_out.csv (3 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'Non_Production_domains_out.csv')
    rows = []

    non_prod_keywords = ['dev', 'staging', 'uat', 'test', 'qa', 'sandbox']

    for i in range(3):
        keyword = random.choice(non_prod_keywords)
        domain = f"{keyword}-{random.choice(DOMAINS)}"

        rows.append({
            'Domain': domain
        })

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['Domain'])
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def generate_cloud_misconfig():
    """Generate Cloud_Misconfig_out.csv (4 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'Cloud_Misconfig_out.csv')
    rows = []

    services = ['MongoDB', 'Elasticsearch', 'Redis', 'MySQL', 'PostgreSQL']

    for i in range(4):
        domain = f"{random.choice(SUBDOMAINS)}.{random.choice(DOMAINS)}"
        ip = generate_random_ip()
        port = random.choice([27017, 9200, 6379, 3306, 5432])
        service = random.choice(services)
        risk = random.choice(CLOUD_RISK_LEVELS)

        rows.append({
            'domain': domain,
            'ip': ip,
            'port': port,
            'service': service,
            'risk': risk
        })

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['domain', 'ip', 'port', 'service', 'risk'])
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def generate_tech_checker():
    """Generate tech_checker_out.csv (15 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'tech_checker_out.csv')
    rows = []

    for i in range(15):
        url = f"https://{random.choice(SUBDOMAINS)}.{random.choice(DOMAINS)}"
        row = {'url': url}

        # Add various technologies
        software_list = ['Apache', 'Nginx', 'PHP', 'WordPress', 'JQuery', 'Bootstrap', 'Microsoft-IIS', 'OpenSSL']
        selected_software = random.sample(software_list, random.randint(1, 4))

        for soft in selected_software:
            if soft in TECHNOLOGIES:
                row[soft] = f"{soft}/{random.choice(TECHNOLOGIES[soft])}"

        rows.append(row)

    fieldnames = ['url', 'Apache', 'Nginx', 'PHP', 'WordPress', 'JQuery', 'Bootstrap', 'Microsoft-IIS', 'OpenSSL']

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def generate_dnstwister_whois():
    """Generate dnstwister_whois_out.csv (5 rows)"""
    filepath = os.path.join(TEST_DATA_DIR, 'dnstwister_whois_out.csv')
    rows = []

    typo_variations = ['exampel.com', 'exampe.com', 'eample.com', 'xample.com', 'examlpe.com']

    for i in range(5):
        domain = random.choice(typo_variations)
        domain_ip = generate_random_ip()

        rows.append({
            'Domain': domain,
            'Domain IP': domain_ip
        })

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['Domain', 'Domain IP'])
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)

def generate_redirectissuefinder():
    """Generate redirectissuefinder_out.txt (simple text file)"""
    filepath = os.path.join(TEST_DATA_DIR, 'redirectissuefinder_out.txt')

    content = []
    for i in range(5):
        domain = f"{random.choice(SUBDOMAINS)}.{random.choice(DOMAINS)}"
        if random.random() > 0.5:
            content.append(f"Original Domain: http://{domain} → Redirect URL: https://{domain}")
        else:
            content.append(f"[!] {domain}: No HTTPS or redirection detected")

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(content))

    return len(content)

def main():
    """Generate all test data"""
    print("Generating Test Data for Reporting Toolkit\n")
    print("=" * 50)

    # Create test_data directory
    os.makedirs(TEST_DATA_DIR, exist_ok=True)
    print(f"Created test data directory: {TEST_DATA_DIR}\n")

    # Generate all CSV files
    generators = [
        ("Recon_out_enriched.csv", generate_recon_out_enriched),
        ("tech_detection_unified.csv", generate_tech_detection_unified),
        ("crt_transparency.csv", generate_crt_transparency),
        ("Other_Buckets_out.csv", generate_other_buckets),
        ("Admin_Login_Enumerator_out.csv", generate_admin_login_enumerator),
        ("Git_Leak_out.csv", generate_git_leak),
        ("S3_Bucket_Check_out.csv", generate_s3_bucket_check),
        ("VNC_Checker_out.csv", generate_vnc_checker),
        ("Email_Security_Audit_out.csv", generate_email_security_audit),
        ("SSL_TLS_Cert_Check_out.csv", generate_ssl_tls_cert_check),
        ("WAF_Checker_out.csv", generate_waf_checker),
        ("Subdomain_Takeover_Checker_out.csv", generate_subdomain_takeover_checker),
        ("Debug_paths_out.csv", generate_debug_paths),
        ("Default_Page_Checker_out.csv", generate_default_page_checker),
        ("Dir_Listing_Checker_out.csv", generate_dir_listing_checker),
        ("Dead_DNS_Checker_out.csv", generate_dead_dns_checker),
        ("Dead_DNS_Resolver_out.csv", generate_dead_dns_resolver),
        ("Detect_Internal_DNS_out.csv", generate_detect_internal_dns),
        ("Non_Production_domains_out.csv", generate_non_production_domains),
        ("Cloud_Misconfig_out.csv", generate_cloud_misconfig),
        ("tech_checker_out.csv", generate_tech_checker),
        ("dnstwister_whois_out.csv", generate_dnstwister_whois),
    ]

    print("Generating CSV files:\n")
    for filename, generator_func in generators:
        try:
            count = generator_func()
            print(f"  ✓ {filename:<45} ({count} rows)")
        except Exception as e:
            print(f"  ✗ {filename:<45} (Error: {e})")

    # Generate text file
    print("\nGenerating text files:\n")
    try:
        count = generate_redirectissuefinder()
        print(f"  ✓ {'redirectissuefinder_out.txt':<45} ({count} entries)")
    except Exception as e:
        print(f"  ✗ {'redirectissuefinder_out.txt':<45} (Error: {e})")

    print("\n" + "=" * 50)
    print("\nSummary:")
    print(f"Test data directory: {TEST_DATA_DIR}")
    print(f"Total files generated: {len(generators) + 1}")
    print("\nYou can now test the report generator with:")
    print(f"  python generate_report.py --input-file {os.path.join(TEST_DATA_DIR, 'Recon_out_enriched.csv')}")

if __name__ == '__main__':
    main()
