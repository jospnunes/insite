#!/usr/bin/env bash
# Local check of the AUR files. Never run by CI (needs makepkg, so Arch Linux).
# Renders the PKGBUILD and .SRCINFO, then checks that the .SRCINFO matches what
# makepkg itself prints and that the PKGBUILD parses.
# Usage: pkg/aur/test.sh [SCRATCH_DIR]
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$(mktemp -d "${1:-${TMPDIR:-/tmp}}/aur-render.XXXXXX")
trap 'rm -rf "$OUT"' EXIT

A=$(printf 'a%.0s' $(seq 64))
B=$(printf 'b%.0s' $(seq 64))

"$HERE/render.sh" 0.1.0 "$A" "$B" "$OUT"
cd "$OUT"
makepkg --printsrcinfo | diff - .SRCINFO
bash -n PKGBUILD
echo "ok: .SRCINFO matches makepkg and PKGBUILD parses"
