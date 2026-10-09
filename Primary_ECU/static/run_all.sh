#!/bin/bash
set -e

ARCHIVE_PATH="${ARCHIVE}"
OUT="./static_out"
mkdir -p "$OUT"

echo "[SBOM] Generating SBOM..."
./static/sbom.sh "$ARCHIVE_PATH" > "$OUT/sbom.json"

echo "[CVE] Running CVE scan..."
./static/cve_scan.sh "$ARCHIVE_PATH" > "$OUT/cve.log"

echo "[LICENSE] Checking licenses..."
./static/license_scan.sh "$ARCHIVE_PATH" > "$OUT/license.log"

echo "[FS] Filesystem scan..."
./static/fs_scan.sh "$ARCHIVE_PATH" > "$OUT/fs.log"

echo "[OK] Static Verification Completed"