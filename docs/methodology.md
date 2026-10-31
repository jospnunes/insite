# Methodology

How insite is built to behave, and how its speed, precision and security grade
were measured. Every number here comes from a run on the files in this
repository. The command-line reference is in
[usage.md](https://github.com/jospnunes/insite/blob/main/docs/usage.md). The
design document, in Portuguese, is
[arquitetura.md](https://github.com/jospnunes/insite/blob/main/docs/arquitetura.md).

## Principles

**Fast enough to be a selling point.** Everything that does not depend on
something else starts at t = 0. The report never waits past its deadline
(`--timeout`, 5 seconds by default). The HTTP-to-HTTPS check on port 80 runs in
parallel with the page, so it does not wait for the main request. The speed is
measured and published (see [Timing](#timing)).

**Correct before fast.** There is no finding without evidence. What could not
be measured is reported as not measured, never as absent. A DNS resolver that
filters records, a bot challenge instead of the page, an error page: each is
said plainly, and nothing is concluded from it. When speed and precision
conflict, precision wins.

**Passive.** insite reads what any visitor would see. It does not scan ports,
fuzz paths or probe for vulnerabilities.

## Timing

The claim is "about a second", and it is measured with
`scripts/measure-time.py`.

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
cases among them. It is the list every speed and precision target is measured
on.

Result, run from a VPS in Boston on 30 Oct 2026:

| Measure | Value |
| --- | --- |
| Median total time, 100 sites | 888 ms |
| Median without the 10 hard cases | 1028 ms |
| Median for the Brazilian sites | 1424 ms |
| Analysis overhead, median, on that VPS | 130 ms (60 to 100 ms on a laptop) |

The analysis overhead is above the 50 ms target. That is accepted for now.

## Precision of the stack detection

Detection uses the [webappanalyzer](https://github.com/enthec/webappanalyzer)
signatures, about 7,600 technologies. Every detection carries the evidence
behind it.

Precision was measured on 20 sites of the reference list, labeled by hand
(`bench/labels.tsv`). Each detection is marked correct, wrong (the evidence
does not show the technology) or uncertain.

| Result | Count |
| --- | --- |
| Correct | 410 |
| Wrong | 2 |
| Uncertain | 17 |

Precision is 0.995 (410 of the 412 detections that could be decided; the 17
uncertain ones are left out).

## Agreement with Wappalyzer

To check that detection did not drift from the reference, insite's results were
compared with the Wappalyzer JavaScript core (`wappalyzer-core@6.10.66`, kept
in `scripts/conformance`) on 90 sites. The F1 score is 0.997.

## Security grade and the Observatory

The security grade runs from A+ to F and follows the scoring of the
[MDN HTTP Observatory](https://github.com/mdn/mdn-http-observatory): points per
test and grade bands, pinned to a version in the repository. It reproduces the
Observatory's tests and numbers, not only the points table. That includes its
quirks, such as "six months" being 180 days, the severity order of cookies and
Subresource Integrity, and scripts with protocol-relative URLs counted as
insecure. Chromium's HSTS preload list is embedded and refreshed with
`scripts/update-hsts-preload.py`.

A grade is shown only when the response represents the site: no bot challenge,
no error status. Responses that are not HTML get a grade, as in the
Observatory.

Comparison: on 26 sites, compared with the Observatory's published scans,
grade and score matched wherever both saw the same page.

One gap is known. The CORS test's -50 case needs a request with an `Origin`
from another origin. insite does not send one, so it does not apply that
deduction.

## Limits

- insite does not replace the dedicated tools. WhatWeb and Wappalyzer go deeper
  on the stack, SSL Labs on TLS, the Observatory on headers, Lighthouse on Web
  Vitals. insite reports on all of these areas in one passive pass, and Web
  Vitals only with `--browser`.
- Sites that challenge non-browser clients give a partial report (exit code 3).
- Browser metrics are lab measurements and carry their profile.
