#!/bin/bash

# Quick NIST M57 Setup Helper
# Downloads and organizes M57 case for testing

set -e

NIST_URL="http://www.cfreds.nist.gov/data/M57-Patents/"
FIXTURE_DIR="tests/fixtures/nist_m57"

mkdir -p "$FIXTURE_DIR"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║          NIST M57 Patents Case Setup                       ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "[*] Fixture directory: $FIXTURE_DIR"
echo ""
echo "[*] To download M57 case files:"
echo "    1. Visit: $NIST_URL"
echo "    2. Download: nps-2008-6701.E01 (primary image)"
echo "    3. Place in: $FIXTURE_DIR/"
echo ""
echo "[*] Alternatively, download via curl (if available):"
echo "    cd $FIXTURE_DIR"
echo "    # Note: Manual download recommended due to file size"
echo ""
echo "[+] Once downloaded, run:"
echo "    cargo test --test m57_integration_test -- --ignored --nocapture"
echo ""
