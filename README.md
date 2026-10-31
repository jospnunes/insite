# insite

X-ray any website from your terminal: network, TLS, DNS, e-mail, security grade, technology stack, SEO and page weight, in about a second.

[Português](https://github.com/jospnunes/insite/blob/main/README.pt-BR.md)

[![CI](https://github.com/jospnunes/insite/actions/workflows/ci.yml/badge.svg)](https://github.com/jospnunes/insite/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jospnunes/insite)](https://github.com/jospnunes/insite/releases/latest)
[![crates.io](https://img.shields.io/crates/v/insite)](https://crates.io/crates/insite)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](https://github.com/jospnunes/insite/blob/main/LICENSE)

![Terminal recording of insite analyzing a website: the request phases fill in as bars, then each module settles on a verdict and the findings are listed](https://raw.githubusercontent.com/jospnunes/insite/main/assets/demo.gif)

## Install

Linux and macOS (on Linux with a glibc older than 2.35 the installer picks the static musl build):

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/jospnunes/insite/releases/latest/download/insite-installer.sh | sh
```

Homebrew (macOS and Linux):

```bash
brew install jospnunes/tap/insite
```

Arch Linux (AUR):

```bash
yay -S insite-bin
```

Debian, Ubuntu, Fedora and relatives: download the package from the [releases page](https://github.com/jospnunes/insite/releases/latest), for x86_64 or aarch64.

```bash
sudo apt install ./insite_*_amd64.deb
sudo dnf install ./insite-*.x86_64.rpm
```

Rust 1.89 or newer:

```bash
cargo install --locked insite
```

Windows, with Scoop:

```powershell
scoop bucket add insite https://github.com/jospnunes/scoop-bucket
scoop install insite
```

Windows, with PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://github.com/jospnunes/insite/releases/latest/download/insite-installer.ps1 | iex"
```

The binaries run on Linux (x86_64 and aarch64, glibc and musl), macOS (Intel and Apple silicon) and Windows x86_64. `--browser` needs an installed Chrome, Chromium, Edge or Brave, and does not run on Windows yet.

## Try it

```
insite wordpress.org                                # one site, the full report
insite --browser wordpress.org                      # adds LCP, CLS and TBT from a real page load
insite wordpress.org example.com mozilla.org        # several sites, one report each
insite --json wordpress.org | jq -r '.modules.security.data.grade'   # just the security grade
insite --save wp.json.gz wordpress.org              # keep the raw snapshot
insite --from wp.json.gz                            # analyze it again, with no network
insite explain sec.hsts.short                       # what a finding means and how to fix it
```

The `--browser` run adds one line to the report:

```
browser   LCP 1.1 s · CLS 0.00 · TBT 18 ms · 50 requests, 1.6 MB · 70% third-party · mobile, unthrottled
```

And `explain` prints:

```
HSTS max-age is shorter than six months  sec.hsts.short · low

The HSTS policy (<value>) lasts less than six months, so browsers that have not visited recently fall back to plain HTTP on the first request.

Fix
Raise `max-age` to at least 15552000 (180 days); a year (31536000) is common.
```

## What it checks

- **network**: redirects, DNS, TCP, TLS, TTFB and download time per phase, HTTP version, IPv6.
- **tls**: certificate, chain, expiry, names, protocol.
- **dns**: records, DNSSEC, SPF, DMARC, DKIM, MTA-STS, CAA.
- **infra**: AS, hosting, CDN, bot challenges.
- **security**: A+ to F grade, scored like the [MDN HTTP Observatory](https://github.com/mdn/mdn-http-observatory).
- **stack**: 7,647 technologies from the [webappanalyzer](https://github.com/enthec/webappanalyzer) signatures, and known vulnerable JavaScript libraries.
- **seo**: indexability, title, description, canonical, headings, Open Graph, robots.txt, sitemap.
- **weight**: HTML size, scripts, render-blocking resources, images, third parties.
- **browser** (`--browser`): LCP, CLS, TBT and FCP, requests and bytes by type, console errors.

<details>
<summary>Every check, module by module</summary>

| Module | What |
| --- | --- |
| network | redirect chain, DNS, TCP, TLS, TTFB and download per phase, HTTP version, IPv6, HTTPS enforcement, retries |
| tls | certificate, chain (incomplete chains diagnosed with the CCADB), expiry, names, key, SCTs, OCSP stapling, protocol |
| dns | A/AAAA/CNAME/NS/MX/CAA, DNSSEC, SPF (includes walked, 10-lookup limit), DMARC, DKIM selectors, MTA-STS, TLS-RPT, BIMI |
| infra | AS and owner, hosting, CDN, server, bot challenges |
| security | A+ to F grade with the [MDN HTTP Observatory](https://github.com/mdn/mdn-http-observatory) scoring, plus mixed content, insecure forms, version leaks, downgrades, security.txt |
| stack | 7,647 technologies from the [webappanalyzer](https://github.com/enthec/webappanalyzer) signatures, each with the evidence behind it and where it was seen (page, DNS or certificate); libraries with a known vulnerable version are flagged using [Retire.js](https://github.com/RetireJS/retire.js) data |
| seo | indexability, title, description, canonical, headings, language, Open Graph, structured data, robots.txt, sitemap |
| weight | HTML size and compression, scripts, render-blocking resources, images, third parties by name |
| browser | with `--browser`: LCP, CLS, TBT and FCP rated, requests and bytes by type, heaviest resources, third-party share, console errors |

</details>

## Why insite

A whole run takes about a second: the median is 888 ms over a 100-site reference list, one site at a time from a VPS in Boston on 30 Oct 2026 ([method](https://github.com/jospnunes/insite/blob/main/docs/methodology.md#timing)).

Every finding carries its evidence, and what insite could not measure shows as "not measured", never as absent. On 20 hand-labeled sites the stack detection has a precision of 0.995 (uncertain detections excluded), and it agrees with the Wappalyzer JavaScript core at F1 0.997 on 90 sites. On 26 sites the security grade and score matched the Observatory's published scans wherever both saw the same page ([comparison](https://github.com/jospnunes/insite/blob/main/docs/methodology.md#security-grade-and-the-observatory)).

It is passive. It reads what any visitor would see, with no port scans, path fuzzing or vulnerability probes.

> **Do not point insite at untrusted targets from a sensitive network.** It follows redirects, and the `Sitemap:` URL in `robots.txt`, to whatever address they point to, private addresses included. A hostile site can make it request an internal one.

## Compared with other tools

Each cell comes from the tool's own README or docs. A dash means they do not mention it.

| | Stack | TLS | Security headers | DNS and e-mail | SEO | Web Vitals |
| --- | --- | --- | --- | --- | --- | --- |
| insite | yes | yes | A+ to F grade | yes | yes | with `--browser` |
| [httpx](https://github.com/projectdiscovery/httpx) | Wappalyzer dataset (`-tech-detect`) | data grab (`-tls-grab`) | CSP header probe | CNAME and IP | - | - |
| [WhatWeb](https://github.com/urbanadventurer/WhatWeb) | 1800+ plugins | - | - | - | - | - |
| [testssl.sh](https://github.com/testssl/testssl.sh) | - | protocols, ciphers, named flaws, certificate | HSTS and others (`--header`) | CAA; MX over STARTTLS (`--mx`) | - | - |
| [Lighthouse](https://github.com/GoogleChrome/lighthouse) | - | HTTPS use only | HSTS, clickjacking, CSP | - | yes | LCP, CLS, TBT |

testssl.sh tests named flaws such as Heartbleed and ROBOT, which insite does not, and Lighthouse also audits accessibility. insite reports on all these areas in one passive pass. It does not replace their depth.

## For AI agents and scripts

`--json` and `--ndjson` print the report as data, one report per site (two with `--ndjson --browser`: `fast`, then `full`), and `--md` writes Markdown you can paste into a model's context. Finding `id` and `params` are stable, titles and texts may change, and `schema_version` follows semver. Exit codes: 0 complete, 1 unreachable, 2 usage error, 3 partial, 130 interrupted.

```
insite --json -m security wordpress.org | jq -c '.modules.security.findings[] | {id, severity, params}'
```

```
{"id":"sec.csp.missing","severity":"medium","params":{"value":""}}
{"id":"sec.hsts.short","severity":"low","params":{"value":"max-age=3600"}}
{"id":"sec.sri.missing","severity":"low","params":{"value":"https://stats.wp.com/e-202644.js"}}
```

Two more findings are trimmed. If an agent picks the targets, the warning above applies.

## Docs and license

- [Usage](https://github.com/jospnunes/insite/blob/main/docs/usage.md): every option, batch mode, browser mode, live output, your own signatures, JSON stability.
- [Methodology](https://github.com/jospnunes/insite/blob/main/docs/methodology.md): principles, timing, precision, the Observatory comparison.
- [Architecture](https://github.com/jospnunes/insite/blob/main/docs/arquitetura.md): the design document, in Portuguese.
- [Changelog](https://github.com/jospnunes/insite/blob/main/CHANGELOG.md).

insite is free software under the GPL-3.0-or-later. AS lookups use Team Cymru's public IP-to-ASN DNS service. insite is not affiliated with or endorsed by any project below.

<details>
<summary>Embedded data and its licenses</summary>

| Data | Source | License |
| --- | --- | --- |
| Technology signatures | [enthec/webappanalyzer](https://github.com/enthec/webappanalyzer) | GPL-3.0 |
| CA certificates disclosed to root programs (names and key identifiers only) | [Common CA Database](https://www.ccadb.org/) | CDLA-Permissive-2.0 |
| Known vulnerable JavaScript library versions (ranges, severities, identifiers) | [Retire.js](https://github.com/RetireJS/retire.js) | Apache-2.0 |
| HSTS preload list | [Chromium](https://source.chromium.org/chromium/chromium/src/+/main:net/http/transport_security_state_static.json) | BSD-3-Clause |
| Security scoring methodology | [MDN HTTP Observatory](https://github.com/mdn/mdn-http-observatory) | MPL-2.0 |
| Trust roots | Mozilla, via [webpki-roots](https://github.com/rustls/webpki-roots) | CDLA-Permissive-2.0 |
| Public suffix list | [publicsuffix.org](https://publicsuffix.org/), via the `psl` crate | MPL-2.0 |

`scripts/` regenerates the embedded data, and the report lists the version of each source it used.

</details>
