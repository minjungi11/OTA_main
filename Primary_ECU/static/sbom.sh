#!/bin/bash
set -e

IMAGE="localhost/seame_hu_app:1.0.0"
ARCHIVE="artifacts/seame_hu_app.tar"
OUTPUT="artifacts/sbom.json"

echo "[+] Saving image to tar archive..."
podman save -o "$ARCHIVE" "$IMAGE"

echo "[+] Generating SBOM from archive..."
trivy image --input "$ARCHIVE" \
    --format cyclonedx --output "$OUTPUT"

echo "[✓] SBOM saved → $OUTPUT"