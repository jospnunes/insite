#!/usr/bin/env python3
"""Make a saved snapshot fit for the fixtures repository.

Cookie values in Set-Cookie headers can be session tokens, so each one is
replaced by a marker; names and attributes stay, since the analysis reads them.
Reads and writes gzipped JSON (`insite --save site.json.gz`).

Usage: scripts/sanitize-snapshot.py in.json.gz out.json.gz
"""

import gzip
import json
import sys

MARKER = "redacted"


def sanitize_cookie(value):
    name, sep, rest = value.partition("=")
    if not sep:
        return value
    _, semi, attributes = rest.partition(";")
    return f"{name}={MARKER}{semi}{attributes}"


def main():
    source, target = sys.argv[1], sys.argv[2]
    with gzip.open(source, "rt", encoding="utf-8") as f:
        snapshot = json.load(f)
    replaced = 0
    for hop in snapshot.get("chain", []):
        for header in hop.get("headers", []):
            if header[0].lower() == "set-cookie":
                header[1] = sanitize_cookie(header[1])
                replaced += 1
    with gzip.open(target, "wt", encoding="utf-8") as f:
        json.dump(snapshot, f, separators=(",", ":"))
    print(f"{target}: {replaced} cookies redacted", file=sys.stderr)


if __name__ == "__main__":
    main()
