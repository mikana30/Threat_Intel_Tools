import csv
import argparse

def main():
    """
    Reads a CSV file containing domains and debug paths, constructs full URLs,
    and saves them to a text file.
    """
    parser = argparse.ArgumentParser(description="Create full URLs from domains and debug paths.")
    parser.add_argument('-i', '--input', required=True, help='Input CSV file with domain and debug_paths columns.')
    parser.add_argument('-o', '--output', required=True, help='Output text file for the full URLs.')
    args = parser.parse_args()

    full_urls = []
    try:
        with open(args.input, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # ---- PATCH START ----
                # Auto-detect header names to support multiple upstream formats
                domain_key = next((k for k in row.keys() if k.lower() in ["domain", "host"]), None)
                path_key = next((k for k in row.keys() if k.lower() in ["debug_paths", "validated_debug_paths", "path", "url_path"]), None)

                if not domain_key or not path_key:
                    print(f"[!] Skipping row (no valid domain/path keys): {row}")
                    continue

                domain = row[domain_key].strip().rstrip('/')
                debug_paths_raw = row[path_key]
                # Handle multiple debug paths separated by semicolons
                debug_paths = [p.strip() for p in debug_paths_raw.split(';') if p.strip()]

                for debug_path in debug_paths:
                    # If the path already includes the full URL (starts with http), use as-is
                    if debug_path.startswith("http://") or debug_path.startswith("https://"):
                        full_urls.append(debug_path)
                    else:
                        url = f"https://{domain}/{debug_path.lstrip('/')}"
                        full_urls.append(url)
                # ---- PATCH END ----

    except FileNotFoundError:
        print(f"[✗] Error: Input file not found at '{args.input}'")
        return
    except Exception as e:
        print(f"[✗] An unexpected error occurred: {e}")
        return

    # Save the constructed URLs to the specified output file
    with open(args.output, 'w', encoding='utf-8') as f:
        for url in full_urls:
            f.write(url + '\n')

    print(f"[✓] Created {len(full_urls)} full debug URLs in {args.output}")

if __name__ == "__main__":
    main()
