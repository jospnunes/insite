#!/usr/bin/env python3
"""Make a saved snapshot fit for the fixtures repository.

Cookie values in Set-Cookie headers can be session tokens, so each one is
replaced by a marker; names and attributes stay, since the analysis reads them.
Reads and writes gzipped JSON (`insite --save site.json.gz`): one snapshot, or
several, which `--save` writes as one JSON document per line.

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


def documents(text):
    """Every JSON document in the text, one per line or pretty-printed."""
    decoder = json.JSONDecoder()
    position = 0
    while True:
        while position < len(text) and text[position].isspace():
            position += 1
        if position >= len(text):
            return
        document, position = decoder.raw_decode(text, position)
        yield document


def sanitize(snapshot):
    """Redacts the cookies of one snapshot in place; returns how many."""
    replaced = 0
    for hop in snapshot.get("chain", []):
        for header in hop.get("headers", []):
            if header[0].lower() == "set-cookie":
                header[1] = sanitize_cookie(header[1])
                replaced += 1
    return replaced


def main():
    source, target = sys.argv[1], sys.argv[2]
    with gzip.open(source, "rt", encoding="utf-8") as f:
        snapshots = list(documents(f.read()))
    replaced = sum(sanitize(snapshot) for snapshot in snapshots)
    with gzip.open(target, "wt", encoding="utf-8") as f:
        for snapshot in snapshots:
            f.write(json.dumps(snapshot, separators=(",", ":")) + "\n")
    print(f"{target}: {len(snapshots)} snapshots, {replaced} cookies redacted", file=sys.stderr)


if __name__ == "__main__":
    main()
