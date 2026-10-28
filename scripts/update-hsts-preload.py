#!/usr/bin/env python3
"""Regenerates crates/core/data/hsts-preload.tsv from Chromium's HSTS preload list.

Browsers ship this list so preloaded domains are only ever reached over HTTPS.
The security grade needs it to follow the Observatory methodology, which gives
preloaded domains credit for HSTS and for redirection. Only the domains in
force-https mode are kept, with whether the entry covers subdomains.

Usage: scripts/update-hsts-preload.py [path-or-url-of-the-json]
Only the Python standard library is needed.
"""

import datetime
import json
import sys
import urllib.request

SOURCE = "https://raw.githubusercontent.com/chromium/chromium/main/net/http/transport_security_state_static.json"
OUT = "crates/core/data/hsts-preload.tsv"


def load(source):
    if source.startswith("https://"):
        with urllib.request.urlopen(source, timeout=120) as response:
            return response.read().decode("utf-8")
    with open(source, encoding="utf-8") as f:
        return f.read()


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else SOURCE
    # The file is JSON with // comment lines.
    text = "\n".join(line for line in load(source).splitlines() if not line.lstrip().startswith("//"))
    entries = json.loads(text)["entries"]
    rows = sorted(
        {
            (e["name"].strip().lower(), "y" if e.get("include_subdomains") else "n")
            for e in entries
            if e.get("mode") == "force-https"
        }
    )
    today = datetime.date.today().strftime("%Y.%m.%d")
    with open(OUT, "w", encoding="utf-8", newline="\n") as out:
        out.write(f"# Chromium HSTS preload list (force-https entries) as of {today}.\n")
        out.write("# Source: net/http/transport_security_state_static.json, Copyright The Chromium Authors,\n")
        out.write("# BSD-style license (https://source.chromium.org/chromium/chromium/src/+/main:LICENSE).\n")
        out.write("# domain\tsubdomains(y/n)\n")
        for name, subdomains in rows:
            out.write(f"{name}\t{subdomains}\n")
    print(f"{len(rows)} domains written to {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
