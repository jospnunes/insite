#!/usr/bin/env bash
# Tells whether a crate version is already on crates.io.
# Usage: pkg/crates-published.sh CRATE VERSION
# Exit status: 0 when published (HTTP 200), 1 when not (HTTP 404), 2 on anything else.
set -uo pipefail

CRATE=${1:?usage: pkg/crates-published.sh CRATE VERSION}
VERSION=${2:?usage: pkg/crates-published.sh CRATE VERSION}

code=$(curl -s -o /dev/null -w '%{http_code}' \
  -H 'User-Agent: insite-release (https://github.com/jospnunes/insite)' \
  "https://crates.io/api/v1/crates/$CRATE/$VERSION") || code=000

case "$code" in
  200) exit 0 ;;
  404) exit 1 ;;
  *)
    echo "crates.io answered HTTP $code for $CRATE $VERSION" >&2
    exit 2
    ;;
esac
