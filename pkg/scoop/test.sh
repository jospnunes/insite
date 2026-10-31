#!/usr/bin/env bash
# Local check of the Scoop manifest. Renders 0.1.0 and checks the fields Scoop reads.
# Usage: pkg/scoop/test.sh [SCRATCH_DIR]
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$(mktemp -d "${1:-${TMPDIR:-/tmp}}/scoop-render.XXXXXX")
trap 'rm -rf "$OUT"' EXIT

H=$(printf 'a%.0s' $(seq 64))

"$HERE/render.sh" 0.1.0 "$H" "$OUT/insite.json"
jq -e --arg h "$H" '
  .version=="0.1.0"
  and .architecture."64bit".hash==$h
  and (.architecture."64bit".url|endswith("/v0.1.0/insite-x86_64-pc-windows-msvc.zip"))
  and .license=="GPL-3.0-or-later"
  and .bin=="insite.exe"
  and .checkver=="github"
  and (.autoupdate.architecture."64bit".url|contains("v$version/"))
  and (.description|endswith("(--browser is not available on Windows yet)"))
' "$OUT/insite.json"

# Bad input must be refused.
if "$HERE/render.sh" 0.1.0 not-a-hash "$OUT/bad.json" 2>/dev/null; then
  echo "render.sh accepted a bad hash" >&2
  exit 1
fi
if "$HERE/render.sh" v0.1 "$H" "$OUT/bad.json" 2>/dev/null; then
  echo "render.sh accepted a bad version" >&2
  exit 1
fi
