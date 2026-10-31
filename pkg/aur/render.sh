#!/usr/bin/env bash
# Renders the AUR package files from PKGBUILD.in.
# Usage: pkg/aur/render.sh VERSION SHA_X86_64 SHA_AARCH64 OUTDIR
# Writes OUTDIR/PKGBUILD and OUTDIR/.SRCINFO. The .SRCINFO is written by hand,
# without makepkg, because the CI runner is Ubuntu; pkg/aur/test.sh checks that
# it matches `makepkg --printsrcinfo` byte for byte.
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 VERSION SHA_X86_64 SHA_AARCH64 OUTDIR" >&2
  exit 2
fi
VERSION=$1
SHA_X86_64=$2
SHA_AARCH64=$3
OUTDIR=$4

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "render.sh: VERSION must look like 1.2.3, got '$VERSION'" >&2
  exit 1
fi
for sha in "$SHA_X86_64" "$SHA_AARCH64"; do
  if ! [[ "$sha" =~ ^[0-9a-f]{64}$ ]]; then
    echo "render.sh: not a sha256 hex digest: '$sha'" >&2
    exit 1
  fi
done

HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUTDIR"

PKGBUILD=$(<"$HERE/PKGBUILD.in")
PKGBUILD=${PKGBUILD//@VERSION@/$VERSION}
PKGBUILD=${PKGBUILD//@SHA_X86_64@/$SHA_X86_64}
PKGBUILD=${PKGBUILD//@SHA_AARCH64@/$SHA_AARCH64}
printf '%s\n' "$PKGBUILD" > "$OUTDIR/PKGBUILD"

# Read the fixed fields back from the rendered PKGBUILD so the two files cannot drift.
pkgdesc=$(sed -n "s/^pkgdesc='\(.*\)'$/\1/p" "$OUTDIR/PKGBUILD")
url=$(sed -n "s/^url='\(.*\)'$/\1/p" "$OUTDIR/PKGBUILD")
base="https://github.com/jospnunes/insite/releases/download/v$VERSION"

{
  printf 'pkgbase = insite-bin\n'
  printf '\tpkgdesc = %s\n' "$pkgdesc"
  printf '\tpkgver = %s\n' "$VERSION"
  printf '\tpkgrel = 1\n'
  printf '\turl = %s\n' "$url"
  printf '\tarch = x86_64\n'
  printf '\tarch = aarch64\n'
  printf '\tlicense = GPL-3.0-or-later\n'
  printf '\toptdepends = chromium: --browser mode (Core Web Vitals)\n'
  printf '\tprovides = insite\n'
  printf '\tconflicts = insite\n'
  printf '\toptions = !debug\n'
  printf '\tsource_x86_64 = insite-%s-x86_64.tar.xz::%s/insite-x86_64-unknown-linux-musl.tar.xz\n' "$VERSION" "$base"
  printf '\tsha256sums_x86_64 = %s\n' "$SHA_X86_64"
  printf '\tsource_aarch64 = insite-%s-aarch64.tar.xz::%s/insite-aarch64-unknown-linux-musl.tar.xz\n' "$VERSION" "$base"
  printf '\tsha256sums_aarch64 = %s\n' "$SHA_AARCH64"
  printf '\n'
  printf 'pkgname = insite-bin\n'
} > "$OUTDIR/.SRCINFO"
