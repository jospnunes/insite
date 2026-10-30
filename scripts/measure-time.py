#!/usr/bin/env python3
"""Measure the total time per site on the reference list.

Runs one site at a time, each in its own process, so that a site's time is not
shared with others and includes what a person waits for: start, collection,
analysis and output. Prints the median (p50) and p90 for the whole list, for the
list without the hard cases (the "site comum" of the speed targets) and per
group, then the slowest sites. Extra arguments after `--` go to insite, for
example `-- --browser`.

Usage: scripts/measure-time.py [--insite PATH] [--out FILE] [bench/sites.tsv] [-- ARGS]
"""

import argparse
import json
import pathlib
import statistics
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


def measure(insite, url, extra):
    started = time.perf_counter()
    proc = subprocess.run([insite, "--ndjson", *extra, url], capture_output=True, text=True)
    wall_ms = (time.perf_counter() - started) * 1000
    # With --browser the last line is the full report.
    lines = proc.stdout.splitlines()
    report = json.loads(lines[-1]) if lines else None
    return wall_ms, report


def summary(label, times):
    if not times:
        return f"{label:<22} {0:>4}"
    p90 = statistics.quantiles(times, n=10, method="inclusive")[8] if len(times) > 1 else times[0]
    return f"{label:<22} {len(times):>4} {statistics.median(times):>8.0f} {p90:>8.0f} {max(times):>8.0f}"


def main():
    argv = sys.argv[1:]
    extra = argv[argv.index("--") + 1 :] if "--" in argv else []
    argv = argv[: argv.index("--")] if "--" in argv else argv

    parser = argparse.ArgumentParser()
    parser.add_argument("sites", nargs="?", default="bench/sites.tsv")
    parser.add_argument("--insite", default="target/release/insite")
    parser.add_argument("--out", default="target/measure-time.tsv")
    args = parser.parse_args(argv)

    sites = read_sites(args.sites)
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    with out.open("w") as f:
        f.write("segment\tinput\twall_ms\tduration_ms\tstatus\n")
        for i, (segment, url) in enumerate(sites, 1):
            wall_ms, report = measure(args.insite, url, extra)
            status = report["outcome"]["status"] if report else "no report"
            duration_ms = report["duration_ms"] if report else float("nan")
            rows.append((segment, url, wall_ms, status))
            f.write(f"{segment}\t{url}\t{wall_ms:.0f}\t{duration_ms:.0f}\t{status}\n")
            print(f"  {i:>3}/{len(sites)} {wall_ms:>6.0f} ms  {url}", file=sys.stderr)

    print(f"{'ms':<22} {'n':>4} {'p50':>8} {'p90':>8} {'max':>8}")
    groups = [
        ("all", lambda s: True),
        ("without hard cases", lambda s: s != "intl-dificil"),
        ("br", lambda s: s.startswith("br-")),
        ("intl", lambda s: s.startswith("intl-")),
    ]
    for label, keep in groups:
        print(summary(label, [wall for segment, _, wall, _ in rows if keep(segment)]))

    print("\nslowest:")
    for segment, url, wall, status in sorted(rows, key=lambda r: -r[2])[:10]:
        print(f"  {wall:>6.0f} ms  {segment:<16} {url:<45} {status}")


if __name__ == "__main__":
    main()
