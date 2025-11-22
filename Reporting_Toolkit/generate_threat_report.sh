#!/bin/bash
# This script automates the generation of the threat intelligence report.

# Accept the input file path as an argument
INPUT_FILE="$1"

if [ -z "$INPUT_FILE" ]; then
  echo "Error: No input file provided. Usage: ./generate_threat_report.sh <path_to_recon_out_enriched.csv>" >&2
  exit 1
fi

# Resolve the path so subsequent lookups (e.g., Admin_Login_Enumerator_out.csv) succeed.
INPUT_FILE="$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$INPUT_FILE")"

if [ ! -f "$INPUT_FILE" ]; then
  echo "Error: Input file '$INPUT_FILE' not found." >&2
  exit 1
fi

# 1. Run the report generation script using the local runtime
echo "Generating report..."
if [ -d "venv" ]; then
  # shellcheck disable=SC1091
  source venv/bin/activate
  python ./generate_report.py --input-file "$INPUT_FILE"
  deactivate
else
  python3 ./generate_report.py --input-file "$INPUT_FILE"
fi

# 2. Create the final client package
echo "Creating client deliverable package..."
cd ..
# Clean up editor lock files if they exist
find report -maxdepth 1 -name '.~lock.*' -delete
zip -r Threat_Report_Package.zip report/

# 3. Generate checksum for the package
echo "Generating checksum for the package..."
sha256sum Threat_Report_Package.zip > Threat_Report_Package_SHA256.txt

# 4. Move files to the final report directory
mv Threat_Report_Package.zip report/
mv Threat_Report_Package_SHA256.txt report/

cd -

echo "Report generation complete. Final package and checksum are in the 'report' directory."
