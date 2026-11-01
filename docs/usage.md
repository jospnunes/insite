# Usage

This is the reference for the `insite` command line. For install steps and a
short tour, see the [README](https://github.com/jospnunes/insite#readme). For
how the numbers were measured, see
[methodology.md](https://github.com/jospnunes/insite/blob/main/docs/methodology.md).

## Synopsis

```
insite [options] <url>...
insite explain <id>
insite explain
insite update
```

A URL can be a bare domain: insite adds `https://`. With no URL, insite reads
them from standard input, one per line.

```
$ insite example.com
$ insite -m dns,tls,security example.com
$ insite --md example.com > report.md
```

## Untrusted targets

Do not point insite at untrusted targets from a sensitive network. It follows
redirects, and the `Sitemap:` URL in `robots.txt`, to whatever address they
point to, private addresses included. A hostile site can make it request an
internal one.

## Options

| Option | What it does |
| --- | --- |
| `-m`, `--modules <list>` | Modules to run, comma-separated: `network`, `tls`, `dns`, `infra`, `security`, `stack`, `seo`, `weight`, `browser`. |
| `-b`, `--browser` | Also load the page in a headless Chrome. See [Browser mode](#browser-mode). |
| `--throttle` | Core Web Vitals comparable to Lighthouse mobile. Implies `--browser`. |
| `--desktop` | Emulate a desktop instead of a phone in the browser. |
| `--browser-timeout <seconds>` | Deadline for the browser, counted from when its browser slot is acquired (the start, unless a batch has to wait for a slot). Default 20, or 60 with `--throttle`. |
| `-j`, `--json` | Print the report as JSON (an array with several sites). Cannot be combined with `--ndjson` or `--md`. |
| `--ndjson` | Print one JSON report per line, as each site finishes. Cannot be combined with `--json` or `--md`. |
| `--md` | Print the report as Markdown, ready to paste into an e-mail or a proposal. |
| `-t`, `--timeout <seconds>` | Deadline for each site. Default 5. |
| `-v`, `--verbose` | Show every section in full, with the evidence. |
| `--save <file>` | Save the raw snapshot, one JSON per line. The file is gzipped when the name ends in `.gz`. |
| `--from <file>` | Analyze snapshots saved with `--save`, without touching the network. |
| `--ua <profile>` | User-Agent: `honest` (`insite/<version>`, the default), `hybrid` (a Chrome string plus insite), `chrome`, or any text. |
| `--lang <tag>` | `Accept-Language` to send. Default: taken from the system locale. |
| `--native-roots` | Validate certificates against the system trust store instead of the embedded Mozilla roots. Needed behind corporate TLS inspection. |
| `-c`, `--concurrency <n>` | Sites analyzed in parallel in batch mode. Default 8. |
| `-h`, `--help` | Print help. |
| `-V`, `--version` | Print the version. |

Examples:

```
$ insite --browser --throttle example.com
$ insite --browser --desktop --browser-timeout 30 example.com
$ insite --save snapshot.json.gz example.com
$ insite --from snapshot.json.gz --json
$ insite --ua hybrid --lang pt-BR example.com
$ insite --native-roots --timeout 10 example.com
```

## Subcommands

### `insite explain [id]`

Describes a finding, why it matters and how to fix it. The `id` is a finding id
such as `sec.hsts.missing`, or a prefix such as `sec`. Without an id, it lists
every finding.

```
$ insite explain sec.hsts.missing
$ insite explain sec
$ insite explain
```

### `insite update`

Downloads the newest webappanalyzer signatures into the cache directory
(`~/.cache/insite/signatures` on Linux, where `$XDG_CACHE_HOME` is honoured;
`~/Library/Caches/insite/signatures` on macOS; `%LOCALAPPDATA%\insite\cache\signatures`
on Windows). Until
then insite uses the embedded set, and it switches to a downloaded set only when
that set is newer.

| Option | What it does |
| --- | --- |
| `--force` | Download and compile even when the signatures are up to date. |
| `--native-roots` | Trust the system's certificate store for the download. |

```
$ insite update
$ insite update --force
```

## Several sites at once

Pass them as arguments, or give a list on standard input:

```
$ insite a.com b.com
$ insite < sites.txt
```

In a list, insite skips blank lines and everything after a `#`.

Up to `--concurrency` sites run at the same time (8 by default). Analyses of
the same registrable domain run one after another, with a pause between them.

`--ndjson` prints one report per line as the sites finish. With `--browser` you
get two lines per site: the `fast` report first, then the `full` one. The
`phase` field tells them apart.

```
$ insite --ndjson a.com b.com c.com
$ insite --ndjson --browser -c 4 a.com b.com
```

`--json` prints one array when there are several sites.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Complete. |
| 1 | Unreachable. |
| 2 | Usage error. |
| 3 | Partial in a way that changes the reading: a module timed out or failed, or the page does not represent the site (for example, a bot challenge). |
| 130 | Interrupted. |

In batch mode the most serious code wins. Ctrl-C prints what has arrived. A
second Ctrl-C quits at once.

## Browser mode

`--browser` needs Chrome, Chromium, Edge or Brave. insite looks on the usual
paths, or you can set `CHROME_PATH`. It runs on Linux and macOS. It does not run
on Windows yet; the browser module reports that it is not available on that
platform.

Metrics are lab measurements, and each carries its profile. An LCP
measured without throttling is not the PageSpeed one. Use `--throttle` for
numbers comparable to Lighthouse mobile, and `--desktop` to measure as a
desktop.

The browser reports LCP, CLS, TBT and FCP with a rating, requests and bytes by
type, the heaviest resources, the third-party share, console errors and the
stack that only JavaScript reveals.

The browser takes its proxy from `HTTPS_PROXY`. Chrome takes no credentials on
the command line, so insite drops a proxy that needs them, prints a warning, and
the browser connects directly.

## Live output

On an interactive terminal, with the default text format, insite draws the
analysis as it happens:

- each request phase fills in as a bar the moment it finishes;
- redirects appear as they are followed;
- every module spins until its data arrives, then settles on its verdict (`✓`,
  `▲` or `✗`) with its summary;
- with `--browser`, the browser step gets its own second part;
- with several sites, a table fills in row by row.

When the run ends, the final screen stays in the scrollback, so you can scroll
and copy it.

```
◆ insite 0.1.0                                                                                  g1.globo.com

  ┌ dns      ███████████▊                                                                        15 ms
  │ tcp                 ███████▎                                                                9.1 ms
  │ tls                         ███████▊                                                        9.7 ms
  │ ttfb                               █████████████████▎                                        21 ms
  │ download                                             █████████████▎                          16 ms
  └ 100 ms  200 · HTTP/2 · no IPv6 · 186.192.83.7 · AS28604 Globo Comunicacao e Participacoes SA
    HTTPS enforced

✓ tls       DigiCert Inc · TLS 1.3 · expires in 52 days
✓ dns       ns04.globo.com · no DNSSEC · CAA
✓ email     smtp.globo.com · SPF -all · DMARC p=none · DKIM default
▲ security   F  ████████████ 0/100
▲ stack     React · Google Tag Manager · jQuery 1.8.3 · reCAPTCHA
· services  Microsoft 365 · Salesforce · Meta
✓ seo       indexable · 1 issue
✓ weight    HTML 152 KB (877 KB uncompressed) · 14 scripts · 1 third party in the HTML

  8 things to look at
  ▲ medium    Content Security Policy allows inline or arbitrary scripts  sec.csp.unsafe_inline
  ▲ medium    No HSTS                                                     sec.hsts.missing
  ▲ medium    Scripts from other domains loaded insecurely                sec.sri.insecure
  …

  insite explain sec.csp.unsafe_inline   ·   -v for evidence   ·   --json
```

The findings are trimmed here; this is the screen left behind when the run
ends.

How it adapts:

- **Colours.** 24-bit when `COLORTERM` says `truecolor` or `24bit`; the
  16-colour palette otherwise.
- **Symbols.** Without UTF-8 in the locale, they fall back to ASCII.
- **Width.** Below 60 columns the bars go away and the lines become compact.
- **Speed.** The animation draws what the analysis produced and adds no
  delay.
- **`--from`.** On an interactive terminal it shows the same final screen,
  without animation.

Live output turns itself off, and the output becomes plain text, when:

- standard output is a pipe or a file;
- you use `--json`, `--ndjson` or `--md`;
- `NO_COLOR` is set to anything non-empty;
- `TERM` is `dumb`.

Plain text looks like this (trimmed; `-v` opens every section with its
evidence):

```
$ insite wordpress.org
wordpress.org → https://wordpress.org/  200  HTTP/2  381 ms
  tcp 5.3 · tls 75 · ttfb 37 · download 12
  HTTPS enforced

stack     WordPress 7.2 · WordPress Block Editor · WordPress Site Editor · Gutenberg 24.3.0 · MySQL
          PHP · Nginx · Google Font API · Google Tag Manager
security  C   score 55 · 4 issues
tls       Let's Encrypt · TLS 1.3 · expires in 54 days
seo       indexable
weight    HTML 37 KB (178 KB uncompressed) · 5 scripts · 1 third party in the HTML

  medium  No Content Security Policy  sec.csp.missing
  low     HSTS max-age is shorter than six months  sec.hsts.short
  low     Scripts from other domains without Subresource Integrity  sec.sri.missing
  low     No X-Content-Type-Options  sec.xcto.missing
```

On the Windows console, colours and width go through
[crossterm](https://github.com/crossterm-rs/crossterm) and have not been checked
by hand. Set `NO_COLOR` for plain text there.

## Your own signatures

Put files in the webappanalyzer format in a `fingerprints` folder inside the
insite configuration directory. insite adds them to the embedded signatures, and they
override technologies of the same name.

| OS | Folder |
| --- | --- |
| Linux | `~/.config/insite/fingerprints/*.json` (`$XDG_CONFIG_HOME/insite/fingerprints` if set) |
| macOS | `~/Library/Application Support/insite/fingerprints/*.json` |
| Windows | `%APPDATA%\insite\fingerprints\*.json` |

insite ignores signatures it cannot load and warns on standard error.

## JSON output

Key on the finding `id` and its `params`: they are stable. Titles and texts may
change between versions. The `schema_version` field follows semver. There is no
published JSON Schema yet.

```
$ insite --json example.com
$ insite --ndjson a.com b.com
```

## Environment

| Variable | Effect |
| --- | --- |
| `NO_COLOR` | Any non-empty value turns off live output and colour. |
| `TERM` | `dumb` turns off live output. |
| `COLORTERM` | `truecolor` or `24bit` selects 24-bit colour. |
| `CHROME_PATH` | Path to the browser for `--browser`. |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | Proxy settings, with curl's conventions, upper or lower case. |
