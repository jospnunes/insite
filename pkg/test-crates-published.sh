#!/usr/bin/env bash
# Checks pkg/crates-published.sh against the live crates.io API.
# Uses serde 1.0.0 (published) and insite 0.1.0 (must not be on crates.io yet).
# Never run by CI.
set -uo pipefail

cd "$(dirname "$0")/.."

fail=0
check() {
  local want=$1 crate=$2 version=$3 got
  pkg/crates-published.sh "$crate" "$version"
  got=$?
  if [ "$got" -ne "$want" ]; then
    echo "FAIL: crates-published.sh $crate $version exited $got, wanted $want"
    fail=1
  else
    echo "ok: crates-published.sh $crate $version exited $got"
  fi
}

check 0 serde 1.0.0
check 1 insite 0.1.0
exit "$fail"
