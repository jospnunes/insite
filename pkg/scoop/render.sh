#!/usr/bin/env bash
# Renders the Scoop manifest for the Windows release archive.
# Usage: pkg/scoop/render.sh VERSION SHA256 OUTFILE
# The description is read from crates/cli/Cargo.toml so the two cannot drift.
# "bin" is a bare file name because dist zips have no wrapper folder: insite.exe
# sits at the archive root
# (https://axodotdev.github.io/cargo-dist/book/artifacts/archives.html).
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 VERSION SHA256 OUTFILE" >&2
  exit 2
fi
VERSION=$1
SHA256=$2
OUTFILE=$3

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "render.sh: VERSION must look like 1.2.3, got '$VERSION'" >&2
  exit 1
fi
if ! [[ "$SHA256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "render.sh: not a sha256 hex digest: '$SHA256'" >&2
  exit 1
fi

HERE=$(cd "$(dirname "$0")" && pwd)
description=$(sed -n 's/^description = "\(.*\)"$/\1/p' "$HERE/../../crates/cli/Cargo.toml")
if [ -z "$description" ]; then
  echo "render.sh: no description found in crates/cli/Cargo.toml" >&2
  exit 1
fi

base="https://github.com/jospnunes/insite/releases/download"
zip="insite-x86_64-pc-windows-msvc.zip"

mkdir -p "$(dirname "$OUTFILE")"
jq -n \
  --arg version "$VERSION" \
  --arg description "$description (--browser is not available on Windows yet)" \
  --arg url "$base/v$VERSION/$zip" \
  --arg autoupdate "$base/v\$version/$zip" \
  --arg hash "$SHA256" '
  {
    version: $version,
    description: $description,
    homepage: "https://github.com/jospnunes/insite",
    license: "GPL-3.0-or-later",
    architecture: { "64bit": { url: $url, hash: $hash } },
    bin: "insite.exe",
    checkver: "github",
    autoupdate: { architecture: { "64bit": { url: $autoupdate } } }
  }' > "$OUTFILE"
