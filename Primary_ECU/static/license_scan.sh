#!/bin/bash
set -e

ARCHIVE="artifacts/seame_hu_app.tar"
OUTPUT="artifacts/license.log"

echo "[+] Running license scan on tar archive..."
trivy image --input "$ARCHIVE" --scanners license \
    > "$OUTPUT"

echo "[✓] License scan complete → $OUTPUT"