#!/usr/bin/env python3
"""Compare User-Agent profiles on the reference list.

Runs the list once per pass, in the order given (default: hybrid, honest, honest,
hybrid, so that a site that grows stricter after the first visits weighs on both
profiles alike), and counts for each profile the sites that answered with a bot
challenge, with a page that does not represent the site (an error status), or
not at all. The profile with fewer challenges and error pages becomes the default.

Usage: scripts/compare-ua.py [--insite PATH] [--passes hybrid,honest,honest,hybrid]
                             [--out DIR] [bench/sites.tsv]
"""

import argparse
import collections
import json
import pathlib
import subprocess
import sys
import time


def read_sites(path):
    sites = []
    for line in pathlib.Path(path).read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        segment, url, *_ = line.split("\t")
        sites.append((segment, url))
    return sites


def run_pass(insite, profile, urls, out):
    started = time.time()
    proc = subprocess.run(
        [insite, "--ndjson", "--ua", profile, "-m", "network,infra,security"],
        input="\n".join(urls) + "\n",
        capture_output=True,
        text=True,
    )
    out.write_text(proc.stdout)
    print(f"  {profile}: {len(proc.stdout.splitlines())} reports in {time.time() - started:.0f} s", file=sys.stderr)
    return [json.loads(line) for line in proc.stdout.splitlines()]


def classify(report):
    """challenge, error page, unreachable or ok."""
    infra = report["modules"]["infra"].get("data") or {}
    if infra.get("challenge"):
        return "challenge"
    if report["outcome"]["status"] == "unreachable":
        return "unreachable"
    if any("does not represent the site" in r for r in report["outcome"].get("reasons", [])):
        return "error page"
    return "ok"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sites", nargs="?", default="bench/sites.tsv")
    parser.add_argument("--insite", default="target/release/insite")
    parser.add_argument("--passes", default="hybrid,honest,honest,hybrid")
    parser.add_argument("--out", default="target/compare-ua")
    parser.add_argument("--pause", type=int, default=60, help="seconds between passes")
    args = parser.parse_args()

    sites = read_sites(args.sites)
    segment_of = {url: segment for segment, url in sites}
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    # outcome[profile][input] -> list of classes, one per pass
    outcome = collections.defaultdict(lambda: collections.defaultdict(list))
    passes = args.passes.split(",")
    for i, profile in enumerate(passes):
        if i:
            time.sleep(args.pause)
        print(f"pass {i + 1}/{len(passes)}", file=sys.stderr)
        for report in run_pass(args.insite, profile, [u for _, u in sites], out / f"{i + 1}-{profile}.ndjson"):
            outcome[profile][report["target"]["input"]].append(classify(report))

    # A site counts as blocked for a profile when any of its passes was.
    print(f"{'profile':<8} {'challenge':>9} {'error page':>10} {'unreachable':>11} {'ok':>4}")
    for profile, by_site in outcome.items():
        worst = collections.Counter()
        for classes in by_site.values():
            for c in ("challenge", "error page", "unreachable", "ok"):
                if c in classes:
                    worst[c] += 1
                    break
        print(f"{profile:<8} {worst['challenge']:>9} {worst['error page']:>10} {worst['unreachable']:>11} {worst['ok']:>4}")

    profiles = list(outcome)
    if len(profiles) == 2:
        a, b = profiles
        print(f"\nsites where {a} and {b} differ:")
        for url in sorted(set(outcome[a]) | set(outcome[b])):
            ca, cb = outcome[a].get(url, []), outcome[b].get(url, [])
            if set(ca) != set(cb):
                segment = segment_of.get(url) or next((s for u, s in segment_of.items() if u in url), "?")
                print(f"  {segment:<16} {url:<45} {a}: {'/'.join(ca):<24} {b}: {'/'.join(cb)}")


if __name__ == "__main__":
    main()
