#!/usr/bin/env python3
"""Regenerates crates/core/data/retire.tsv from the Retire.js vulnerability repository.

Retire.js (https://github.com/RetireJS/retire.js, Apache-2.0, the license covers
the whole repository including repository/) keeps a list of JavaScript libraries
with the version ranges that have known vulnerabilities. We keep only what the
stack analysis needs to match a detected version: the component name, the range
(`atOrAbove` inclusive, `below` exclusive), the severity, the identifiers
(CVE, else the GitHub advisory), a short summary, and the versions the range
excludes. The extractors (file names, hashes, regexes) are not embedded.

The file is read at a pinned commit, so the data only changes when this script's
COMMIT does. To update, set COMMIT to a newer commit of the default branch (the
date is fetched from the GitHub API) and run the script.

Usage: scripts/update-retire.py [path-of-the-json]
With a path, the commit and date are not looked up: pass them in the environment
(RETIRE_COMMIT, RETIRE_DATE as YYYY-MM-DD). Only the Python standard library is
needed.
"""

import datetime
import json
import os
import sys
import urllib.request

COMMIT = "970fc886e7eb1002bc5e989f3f480ab5853fc82a"
FILE = "repository/jsrepository-v6.json"
OUT = "crates/core/data/retire.tsv"
# The summary is a hint, not the advisory: the identifiers lead to that.
SUMMARY_MAX = 110
# Entries that only exist to document the format or to be skipped.
SKIP = {"retire-example", "dont check"}


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "insite-update-retire"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read().decode("utf-8")


def commit_date(commit):
    try:
        info = json.loads(fetch(f"https://api.github.com/repos/RetireJS/retire.js/commits/{commit}"))
        return info["commit"]["committer"]["date"][:10]
    except Exception as error:  # the date is informative; the data does not depend on it
        print(f"commit date not found ({error}); using today", file=sys.stderr)
        return datetime.date.today().isoformat()


def clean(text):
    return " ".join(str(text).replace("\t", " ").split())


def shorten(text):
    text = clean(text)
    if len(text) <= SUMMARY_MAX:
        return text
    cut = text[: SUMMARY_MAX - 1].rsplit(" ", 1)[0].rstrip(",;:.(")
    return cut + "…"


def main():
    if len(sys.argv) > 1:
        with open(sys.argv[1], encoding="utf-8") as f:
            text = f.read()
        commit = os.environ.get("RETIRE_COMMIT", "local")
        date = os.environ.get("RETIRE_DATE", datetime.date.today().isoformat())
    else:
        commit = COMMIT
        text = fetch(f"https://raw.githubusercontent.com/RetireJS/retire.js/{commit}/{FILE}")
        date = commit_date(commit)
    repository = json.loads(text)

    rows = []
    for component, entry in repository.items():
        if component in SKIP:
            continue
        for v in entry.get("vulnerabilities", []):
            below = v.get("below")
            severity = v.get("severity")
            if not below or severity not in ("low", "medium", "high", "critical"):
                continue
            ids = v.get("identifiers", {})
            cves = ids.get("CVE") or []
            if isinstance(cves, str):
                cves = [cves]
            advisories = [ids["githubID"]] if ids.get("githubID") and not cves else []
            rows.append(
                (
                    clean(component),
                    clean(v.get("atOrAbove", "")),
                    clean(below),
                    severity,
                    ",".join(clean(i) for i in cves + advisories),
                    ",".join(clean(x) for x in v.get("excludes", [])),
                    shorten(ids.get("summary", "")),
                )
            )
    rows.sort()
    with open(OUT, "w", encoding="utf-8", newline="\n") as out:
        out.write(f"# Retire.js vulnerability repository ({FILE}) at RetireJS/retire.js@{commit[:7]} ({date}).\n")
        out.write("# Source: https://github.com/RetireJS/retire.js, Apache-2.0 (https://github.com/RetireJS/retire.js/blob/master/LICENSE.md).\n")
        out.write("# component\tat_or_above\tbelow\tseverity\tidentifiers\texcludes\tsummary\n")
        for row in rows:
            out.write("\t".join(row) + "\n")
    print(f"{len(rows)} vulnerabilities written to {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
