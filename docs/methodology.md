# Methodology

How insite is built to behave, and how its speed, precision and security grade
were measured. You can rerun the timing with `scripts/measure-time.py` on
`bench/sites.tsv`, and the labels behind the precision number are in
`bench/labels.tsv`. The 26-site Observatory comparison used the Observatory's
published scans. The command-line reference is in
[usage.md](https://github.com/jospnunes/insite/blob/main/docs/usage.md). How the code
is built is in
[architecture.md](https://github.com/jospnunes/insite/blob/main/docs/architecture.md).

## Principles

**Fast enough to notice.** Work that depends on nothing else
starts at t = 0. The report does not wait past its deadline (`--timeout`, 5
seconds by default). The HTTP-to-HTTPS check on port 80 runs in parallel with
the page, so it does not wait for the main request. [Timing](#timing) has the
numbers.

**Correct before fast.** There is no finding without evidence. insite reports what it could
not measure as not measured, and does not call it absent. It does the same for
a DNS resolver that filters records, a bot challenge instead of the page and an
error page, and draws no conclusion from them. When speed and precision
conflict, precision wins.

**Passive.** insite reads what any visitor would see. It does not scan ports,
fuzz paths or probe for vulnerabilities.

## Timing

The "about a second" figure comes from `scripts/measure-time.py`.

The script runs the reference list one site at a time, each in its own
process, so a site's time is not shared with others. The time includes what a
person waits for: start, collection, analysis and output. It prints the median
(p50) and p90 for the whole list, for the list without the hard cases, and per
group, then the slowest sites. Arguments after `--` go to insite, for example
`-- --browser`.

```
scripts/measure-time.py [--insite PATH] [--out FILE] [bench/sites.tsv] [-- ARGS]
```

The reference list is `bench/sites.tsv`: 100 sites, in segments, with ten hard
cases among them. All speed and precision targets use this list.

Result, run from a VPS in Boston on 30 Oct 2026:

| Measure | Value |
| --- | --- |
| Median total time, 100 sites | 888 ms |
| Median without the 10 hard cases | 1028 ms |
| Brazilian sites, slower from the VPS | 1424 ms |
| Analysis overhead, median, on that VPS | 130 ms (60 to 100 ms on a laptop) |

The analysis overhead is above the 50 ms target. Known limit.

## Precision of the stack detection

Detection uses the [webappanalyzer](https://github.com/enthec/webappanalyzer)
signatures: 7,647 technologies in the embedded set, as the build report
(`sigc-report.txt`, written by `crates/core/build.rs`) counts them. Each
detection carries its evidence.

Precision comes from 20 sites of the reference list, with detections labeled by
hand (`bench/labels.tsv`). Each detection gets a verdict: correct, wrong (the
evidence does not show the technology) or uncertain.

| Result | Count |
| --- | --- |
| Correct | 410 |
| Wrong | 2 |
| Uncertain | 17 |

Precision is 0.995: 410 correct out of 412 decided, with the 17 uncertain
detections excluded.

## Agreement with Wappalyzer

We compared insite's results with the Wappalyzer JavaScript core (`wappalyzer-core@6.10.66`, kept
in `scripts/conformance`) on 90 sites. The F1 score is 0.997.

## Security grade and the Observatory

The security grade runs from A+ to F and follows the scoring of the
[MDN HTTP Observatory](https://github.com/mdn/mdn-http-observatory): points per
test and grade bands, with the version pinned in the repository. It reproduces the
Observatory's tests and numbers, not only the points table. That includes its
quirks, such as "six months" being 180 days, the severity order of cookies and
Subresource Integrity, and scripts with protocol-relative URLs counted as
insecure. insite embeds Chromium's HSTS preload list, and
`scripts/update-hsts-preload.py` refreshes it.

insite shows a grade only when the response represents the site: no bot challenge,
no error status. Responses that are not HTML get a grade, as in the
Observatory.

Comparison: we ran insite on 26 sites and compared grade and score with the
Observatory's published scans of the same sites. They matched wherever both saw
the same page.

One gap is known. The CORS test's -50 case needs a request with an `Origin`
from another origin. insite does not send one, so it does not apply that
deduction.

## Limits

- Sites that challenge non-browser clients give a partial report (exit code 3).
- Browser metrics are lab measurements and carry their profile.
