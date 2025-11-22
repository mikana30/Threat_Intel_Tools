import csv
import argparse
import os

def extract_urls(input_file, output_file):
    if not os.path.exists(input_file):
        print(f"[!] File not found: {input_file}")
        return

    with open(input_file, 'r', newline='', encoding='utf-8') as infile, \
         open(output_file, 'w', newline='', encoding='utf-8') as outfile:

        reader = csv.DictReader(infile)
        reader.fieldnames = [field.strip().lower() for field in reader.fieldnames]

        fieldnames = ['origin_domain', 'bucket_url', 'example_key_url']
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for raw_row in reader:
            row = {k.strip().lower(): v for k, v in raw_row.items()}

            status_val = row.get('status', '').strip().lower()
            risk_val = row.get('risk', '').strip().lower()

            # Flexible match to catch weird encodings or formats
            if 'public' in status_val and 'high risk' in risk_val:
                domain = row.get('origin_domain', '').strip()
                bucket = row.get('bucket_name', '').strip()
                region = row.get('region', '').strip()
                keys_raw = row.get('example_keys', '').strip()

                keys = [k.strip() for k in keys_raw.replace('\n', ',').split(',') if k.strip()]

                for key in keys:
                    bucket_url = f"https://{bucket}.s3.{region}.amazonaws.com"
                    file_url = f"{bucket_url}/{key}"
                    writer.writerow({
                        'origin_domain': domain,
                        'bucket_url': bucket_url,
                        'example_key_url': file_url
                    })

    print(f"[+] Done. Output saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Extract accessible S3 URLs from bucket scan results.")
    parser.add_argument('-i', '--input', required=True, help='Input CSV file')
    parser.add_argument('-o', '--output', required=True, help='Output CSV file for URLs')

    args = parser.parse_args()
    extract_urls(args.input, args.output)

if __name__ == '__main__':
    main()
