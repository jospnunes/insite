# insite

[![CI](https://github.com/jospnunes/insite/actions/workflows/ci.yml/badge.svg)](https://github.com/jospnunes/insite/actions/workflows/ci.yml)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/jospnunes/insite)](https://github.com/jospnunes/insite/releases/latest)

Full X-ray of a website from the terminal: network, TLS, DNS and e-mail,
infrastructure, technology stack, security grade, technical SEO and page weight,
in about a second, from a single binary. With `--browser`, also Core Web Vitals
and the stack only JavaScript reveals.

"About a second" is measured: `scripts/measure-time.py` gives a median of
888 ms for the whole run over the 100-site reference list (`bench/sites.tsv`),
one site at a time from a VPS in Boston, on 30 Oct 2026.

Other tools cover one slice each: WhatWeb and Wappalyzer for the stack, SSL
Labs for TLS, the MDN HTTP Observatory for headers, Lighthouse for Web Vitals.
insite reports on all of these areas in one passive pass from the terminal
(Web Vitals only with `--browser`). It is not a replacement for their depth.

```
$ insite wordpress.org
wordpress.org → https://wordpress.org/  200  HTTP/2  381 ms
  tcp 5.3 · tls 75 · ttfb 37 · download 12
  HTTPS enforced

stack     WordPress 7.2 · WordPress Block Editor · Gutenberg 24.3.0 · MySQL · PHP · Nginx
          Google Font API · Google Tag Manager · HSTS · Let's Encrypt · Open Graph · RSS
security  C   score 55 · 4 issues
tls       Let's Encrypt · TLS 1.3 · expires in 54 days
seo       indexable
weight    HTML 37 KB (178 KB uncompressed) · 5 scripts · 1 third party in the HTML

  medium  No Content Security Policy  sec.csp.missing
  low     HSTS max-age is shorter than six months  sec.hsts.short
  low     Scripts from other domains without Subresource Integrity  sec.sri.missing
  low     No X-Content-Type-Options  sec.xcto.missing
```

(Output trimmed; `-v` opens every section with its evidence.)

## Principles

- **Fast enough to be a selling point.** Everything that does not depend on
  something else starts at t = 0; the report never waits past its deadline
  (the timing method is above).
- **Correct before fast.** No finding without evidence. What could not be
  measured is reported as not measured, never as absent: a DNS resolver that
  filters records, a bot challenge instead of the page, an error page — each is
  said plainly, and nothing is concluded from it.
- **Passive.** It reads what any visitor would see. No port scans, no path
  fuzzing, no vulnerability probes.

## What it reports

| Module | What |
| --- | --- |
| network | redirect chain, DNS, TCP, TLS, TTFB and download per phase, HTTP version, IPv6, HTTPS enforcement, retries |
| tls | certificate, chain (incomplete chains diagnosed with the CCADB), expiry, names, key, SCTs, OCSP stapling, protocol |
| dns | A/AAAA/CNAME/NS/MX/CAA, DNSSEC, SPF (includes walked, 10-lookup limit), DMARC, DKIM selectors, MTA-STS, TLS-RPT, BIMI |
| infra | AS and owner, hosting, CDN, server, bot challenges |
| security | A+ to F grade with the [MDN HTTP Observatory](https://github.com/mdn/mdn-http-observatory) scoring, plus mixed content, insecure forms, version leaks, downgrades, security.txt |
| stack | ~7,600 technologies from the [webappanalyzer](https://github.com/enthec/webappanalyzer) signatures, each with the evidence behind it |
| seo | indexability, title, description, canonical, headings, language, Open Graph, structured data, robots.txt, sitemap |
| weight | HTML size and compression, scripts, render-blocking resources, images, third parties by name |
| browser | with `--browser`: LCP, CLS, TBT and FCP rated, requests and bytes by type, heaviest resources, third-party share, console errors |

The security grade reproduces the Observatory's tests and numbers; on 26 sites
compared with its published scans, grade and score matched wherever both saw
the same page. The one known gap: the CORS test's −50 case needs a
cross-origin request, which insite does not send.

## Install

Linux and macOS (on Linux with a glibc older than 2.35, the installer picks
the static musl build):

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/jospnunes/insite/releases/latest/download/insite-installer.sh | sh
```

Windows (PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://github.com/jospnunes/insite/releases/latest/download/insite-installer.ps1 | iex"
```

The archives for each platform are on the
[releases page](https://github.com/jospnunes/insite/releases). From source,
with Rust 1.89 or newer:

```bash
cargo install --path crates/cli
```

**Platforms:** Linux x86_64 and aarch64 (glibc and musl), macOS (Intel and
Apple silicon) and Windows x86_64. The minimum supported Rust version (MSRV) is
1.89. `--browser` needs Chrome, Chromium, Edge or Brave and does not run on
Windows yet.

## Usage

```
insite [options] <url>...
  -m, --modules <list>       network,tls,dns,infra,security,stack,seo,weight,browser
  -b, --browser              also load the page in a headless Chrome
      --throttle             Core Web Vitals comparable to Lighthouse mobile (implies --browser)
      --desktop              emulate a desktop instead of a phone in the browser
  -j, --json | --ndjson | --md
  -t, --timeout <s>          deadline per site (default 5)
      --browser-timeout <s>  deadline for the browser (default 20, 60 with --throttle)
  -v, --verbose              every section in full, with evidence
      --save <file>          save the raw snapshot (gzip with .gz)
      --from <file>          analyze saved snapshots without network
      --ua <profile>         honest (default), hybrid, chrome, or any text
      --lang <tag>           Accept-Language (default: from the system locale)
      --native-roots         trust the system's certificate store
  -c, --concurrency <n>      sites in parallel in batch mode (default 8)

insite explain <id>          a finding, why it matters and how to fix it
insite update                newest webappanalyzer signatures into the cache
      --force                download and compile even when they are up to date
      --native-roots         trust the system's certificate store for the download
```

**Do not point it at untrusted targets from a sensitive network.** insite
follows redirects, and the `Sitemap:` URL in `robots.txt`, to whatever address
they point to, private addresses included. A hostile site can make it request
an internal one.

Several sites at once: `insite a.com b.com`, or a list on standard input
(`insite < sites.txt`). Analyses of the same registrable domain run one after
another, with a pause between them. `--ndjson` prints one report per line as
sites finish (with `--browser`, two per site: the `fast` report, then the `full` one,
told apart by the `phase` field); `--md` writes a report ready to paste into an e-mail.

**Exit codes:** 0 complete; 1 unreachable; 2 usage error; 3 partial in a way
that changes the reading (a module timed out or failed, or the page does not
represent the site); 130 interrupted. In batch mode the most serious wins.
Ctrl-C prints what has arrived; a second Ctrl-C quits at once.

**Browser mode** needs Chrome, Chromium, Edge or Brave (found on the usual
paths, or set `CHROME_PATH`). It runs on Linux and macOS; Windows support is
planned. Metrics are lab measurements and always carry their profile: an LCP
measured without throttling is not the PageSpeed one.

**Own signatures:** files in the webappanalyzer format in
`~/.config/insite/fingerprints/*.json` (macOS: `~/Library/Application
Support/insite`, Windows: `%APPDATA%\insite`) are added to the embedded ones and
override technologies of the same name.

**JSON:** consumers should key on finding `id` and `params`, which are stable;
titles and texts may change. `schema_version` follows semver.

## Data and licenses

insite is free software under the **GPL-3.0-or-later**. It embeds:

| Data | Source | License |
| --- | --- | --- |
| Technology signatures | [enthec/webappanalyzer](https://github.com/enthec/webappanalyzer) | GPL-3.0 |
| CA certificates disclosed to root programs (names and key identifiers only) | [Common CA Database](https://www.ccadb.org/) | CDLA-Permissive-2.0 |
| HSTS preload list | [Chromium](https://source.chromium.org/chromium/chromium/src/+/main:net/http/transport_security_state_static.json) | BSD-3-Clause |
| Security scoring methodology | [MDN HTTP Observatory](https://github.com/mdn/mdn-http-observatory) | MPL-2.0 |
| Trust roots | Mozilla, via [webpki-roots](https://github.com/rustls/webpki-roots) | CDLA-Permissive-2.0 |
| Public suffix list | [publicsuffix.org](https://publicsuffix.org/), via the `psl` crate | MPL-2.0 |

AS lookups use Team Cymru's public IP-to-ASN DNS service. insite is not
affiliated with, or endorsed by, any of these projects. `scripts/` regenerates
the embedded data; the report lists the version of each source it used.

[docs/arquitetura.md](docs/arquitetura.md) is the design document, in
Portuguese: decisions and trade-offs.

---

## Em português

Raio-x completo de um site pelo terminal: rede, TLS, DNS e e-mail,
infraestrutura, stack, nota de segurança, SEO técnico e peso da página, em
cerca de um segundo, num binário único. Com `--browser`, também Core Web Vitals
e a stack que só o JavaScript revela.

- **Rápido o bastante para ser argumento de venda**, e **correto antes de
  rápido**: nada de achado sem evidência; o que não pôde ser medido aparece como
  não medido, nunca como ausente.
- **Passivo**: lê o que qualquer visitante veria. Sem varredura de portas, sem
  testes de vulnerabilidade.
- **Nota de segurança** com a metodologia do MDN HTTP Observatory, conferida
  contra os resultados publicados por ele.

Instalação: `cargo install --path crates/cli` (Rust 1.89 ou mais novo). Uso:
`insite exemplo.com.br`; vários sites: `insite a.com b.com` ou uma lista pela
entrada padrão. `insite explain <id>` explica cada achado e como corrigir.
Formatos: terminal, `--json`, `--ndjson` e `--md` (relatório pronto para
cliente).

Licença GPL-3.0-or-later. As bases embutidas e suas licenças estão na tabela
acima. O desenho completo está em [docs/arquitetura.md](docs/arquitetura.md).
