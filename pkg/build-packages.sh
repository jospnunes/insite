#!/usr/bin/env bash
# Build the .deb and .rpm for one architecture with nfpm.
# Usage: pkg/build-packages.sh VERSION ARCH BIN OUTDIR
#   VERSION  package version without the leading v, such as 0.1.0
#   ARCH     x86_64 or aarch64
#   BIN      path to the insite binary for that architecture
#   OUTDIR   directory that receives the two packages
# Set NFPM to the nfpm binary when it is not on PATH.
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 VERSION ARCH BIN OUTDIR" >&2
  exit 2
fi
version=$1
arch=$2
bin=$3
outdir=$4

case "$arch" in
  x86_64) deb_arch=amd64 ;;
  aarch64) deb_arch=arm64 ;;
  *)
    echo "$0: unsupported ARCH '$arch' (use x86_64 or aarch64)" >&2
    exit 2
    ;;
esac

if [ ! -f "$bin" ]; then
  echo "$0: binary not found: $bin" >&2
  exit 2
fi

root=$(cd "$(dirname "$0")/.." && pwd)
nfpm=${NFPM:-nfpm}
mkdir -p "$outdir"
bin=$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")

# nfpm resolves LICENSE and README.md relative to the working directory.
cd "$root"
export VERSION="$version" BIN="$bin" ARCH="$deb_arch"
"$nfpm" package --config pkg/nfpm.yaml --packager deb \
  --target "$outdir/insite_${version}_${deb_arch}.deb"
"$nfpm" package --config pkg/nfpm.yaml --packager rpm \
  --target "$outdir/insite-${version}-1.${arch}.rpm"
