#!/bin/bash
set -e

IMAGE="localhost/seame_hu_app:1.0.0"
OUTPUT="artifacts/fs_scan.log"
ROOT="artifacts/fs_root"

mkdir -p "$ROOT"

echo "[+] Extracting container filesystem..."
CID=$(podman create "$IMAGE")
podman export "$CID" | tar -x -C "$ROOT"

echo "[+] Running FS scan..."
trivy fs "$ROOT" > "$OUTPUT"

echo "[+] Cleaning temp container..."
podman rm "$CID"

echo "[✓] Filesystem scan complete → $OUTPUT"