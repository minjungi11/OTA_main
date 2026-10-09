#!/bin/bash
set -e

ARCHIVE="artifacts/seame_hu_app.tar"
OUTPUT="artifacts/cve.log"

echo "[+] Running CVE scan on tar archive..."
trivy image --input "$ARCHIVE" \
    --severity HIGH,CRITICAL \
    --ignore-unfixed \
    > "$OUTPUT"

echo "[✓] CVE scan complete → $OUTPUT"