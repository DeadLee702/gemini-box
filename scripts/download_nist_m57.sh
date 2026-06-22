#!/bin/bash

# NIST CFReDS M57 Download Script
# Downloads the M57 case files for real-world forensic testing

set -e

echo "[*] NIST M57 Case Download & Setup"
echo "===================================="
echo ""

# Create fixtures directory
mkdir -p tests/fixtures/nist_m57

cd tests/fixtures/nist_m57

echo "[*] Downloading NIST M57 case metadata..."
# M57 case metadata and documentation
curl -O http://www.cfreds.nist.gov/data/M57-Patents/M57-Patents-Scenario.pdf 2>/dev/null || echo "[!] Could not download scenario PDF"

echo "[*] M57 case includes:"
echo "  - nps-2008-6701.E01 (primary disk image)"
echo "  - nps-2008-6702.E01 (secondary disk image)"
echo "  - Known incident types: filesystem tampering, log modification, file deletion"
echo ""

echo "[+] Setup complete. Next steps:"
echo "  1. Download E01 files from http://www.cfreds.nist.gov/data/M57-Patents/"
echo "  2. Place in tests/fixtures/nist_m57/"
echo "  3. Run: cargo run --release --bin e01_extract -- tests/fixtures/nist_m57/nps-2008-6701.E01"
echo ""
