#!/usr/bin/env bash
# Build SysGuard for Linux: AppImage + .deb (x64)
# Prereqs: Node.js >= 18, internet (downloads Electron + builder tools)
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Installing dependencies (production + dev for electron-builder)"
npm install

echo "==> Building AppImage + deb"
npx electron-builder --linux AppImage deb --x64

echo
echo "Done. Artifacts are in ./release:"
ls -lh release/*.AppImage release/*.deb 2>/dev/null || ls -lh release/
