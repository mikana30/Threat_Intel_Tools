import argparse

def identify_non_prod_domains(input_file, output_file):
    non_prod_keywords = ['dev', 'test', 'staging', 'qa', 'uat', 'sandbox', 'stage', 'demo']

    with open(input_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    with open(output_file, 'w') as out:
        for domain in domains:
            if any(k in domain.lower() for k in non_prod_keywords):
                out.write(domain + '\n')
                print(f"Non-prod domain found: {domain}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Identify non-production domains in a list.")
    parser.add_argument("-i", "--input", required=True, help="Input file with domain names")
    parser.add_argument("-o", "--output", required=True, help="Output file for non-production domains")

    args = parser.parse_args()
    identify_non_prod_domains(args.input, args.output)
