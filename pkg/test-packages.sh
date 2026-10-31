#!/usr/bin/env bash
# Local check of the .deb and .rpm packages. Never run by CI.
# Builds insite in a Debian bookworm container (so the glibc matches the test
# images), packages it with nfpm and installs it in Debian and Fedora containers.
# Usage: pkg/test-packages.sh SCRATCH_DIR
set -euo pipefail

SCRATCH=${1:?usage: pkg/test-packages.sh SCRATCH_DIR}
NFPM_VERSION=2.48.0
REPO=$(cd "$(dirname "$0")/.." && pwd)
OUT="$SCRATCH/out"
mkdir -p "$SCRATCH/cargo-target" "$SCRATCH/nfpm" "$OUT"

docker run --rm -e CARGO_BUILD_JOBS=4 \
  -v "$REPO":/src:ro -v "$SCRATCH/cargo-target":/target \
  -w /src rust:1-bookworm \
  cargo build --release -p insite --target-dir /target

if [ ! -x "$SCRATCH/nfpm/nfpm" ]; then
  url="https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}"
  curl -fsSL -o "$SCRATCH/nfpm/nfpm.tgz" "$url/nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz"
  tar -xzf "$SCRATCH/nfpm/nfpm.tgz" -C "$SCRATCH/nfpm" nfpm
fi
export NFPM="$SCRATCH/nfpm/nfpm"

cd "$REPO"
pkg/build-packages.sh 0.1.0 x86_64 "$SCRATCH/cargo-target/release/insite" "$OUT"

docker run --rm -v "$OUT":/p debian:stable-slim sh -c \
  'apt-get update -qq && apt-get install -y -qq /p/insite_0.1.0_amd64.deb >/dev/null && insite --version && dpkg-deb -c /p/insite_0.1.0_amd64.deb'
docker run --rm -v "$OUT":/p fedora:latest sh -c \
  'dnf install -y -q /p/insite-0.1.0-1.x86_64.rpm && insite --version && rpm -qp --suggests /p/insite-0.1.0-1.x86_64.rpm'
