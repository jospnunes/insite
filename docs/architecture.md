# Architecture

insite is a command-line tool that reports on a website from a single binary: network timings, TLS, DNS and e-mail,
hosting, technology stack, security headers, technical SEO and page weight. It is passive: it requests the URL it was
given, as a browser would, and never scans ports, fuzzes paths or probes for vulnerabilities. It sends no telemetry. Its
traffic is the analyzed site and the hosts it redirects to (with `--browser`, whatever the page loads), DNS, and, for
`insite update`, GitHub.

This document explains how the code fits together. Options and output are in
[usage.md](https://github.com/jospnunes/insite/blob/main/docs/usage.md); how the speed, precision and grade figures were
measured is in [methodology.md](https://github.com/jospnunes/insite/blob/main/docs/methodology.md).

## Overview

Collection produces a `Snapshot`, analysis turns the `Snapshot` into a `Report`, and the renderers draw the `Report`.
The phases share only those two types.

```
            CLI: parse arguments, start t = 0, hold the deadline
                                 │
  ┌─ collect (async; the only code that touches the network) ─────────┐
  │  connection engine  │  DNS records, SPF, AS lookup  │  browser   │
  └──────────────────────────────┬─────────────────────────────────────┘
                                 ▼
                      Snapshot   (--save writes it, --from reads it)
                                 │
  ┌─ analyze (pure functions: no sockets, no clock) ──────────────────┐
  │  HTML extraction → PageFacts → one analyzer per module            │
  └──────────────────────────────┬─────────────────────────────────────┘
                                 ▼
                   Report   (schema_version, one block per module)
                ┌────────────────┼─────────────────┐
            terminal       JSON / NDJSON        Markdown
```

Analysis never opens a socket and never reads the clock. When it needs "now", for the days left on a certificate, it
uses the `collected_at` stored in the snapshot. That lets `--from` re-analyze a saved snapshot offline and keeps tests
simple: build a snapshot, assert on the report. Each analyzer runs inside `catch_unwind`, so a panic becomes a module
with status `failed` instead of a crash. With `--browser` the snapshot closes twice: the fast report is built first,
then insite adds the browser data and runs the analysis again.

## Code layout

```
crates/core/     insite-core: collection, analysis and the report types
  src/collect/     connection engine, DNS, proxy, deadline, progress events, browser/ (DevTools Protocol client)
  src/extract/     HTML extraction into PageFacts, charset detection
  src/analyze/     one file per module, plus spf.rs, content.rs, vulnerable.rs
  src/detect/      signature engine and element index
  findings/        one Markdown file per finding id
  data/            signatures, corrections, providers, CCADB, Retire.js, HSTS preload
  tests/           integration tests against local servers
crates/sigc/     insite-sigc: the signature compiler, used by build.rs and by `insite update`
crates/cli/      insite: arguments, scheduler, text and Markdown renderers, src/live/
bench/           the 100-site reference list and the hand-labeled detections
scripts/         regenerate embedded data, measure timing, compare against Wappalyzer
```

Data and findings sit inside `crates/core` because a published crate holds only its own files. `insite-core` does not
depend on the CLI.

## Target and input

A bare domain gets `https://`, only `http` and `https` are accepted, and international names go to punycode on the wire
and appear with accents in the report. insite removes `user:pass@` from the URL, warns about it, and neither sends nor
saves it. An `http://` input or an explicit port starts the chain without a separate port 80 check. An IP address is
sent without SNI, and the DNS module is skipped for it. A URL with a path is the page itself, and helper files come from
the origin root. The final origin is the origin of the first response that is not a redirect, and most modules describe
it. DNS and e-mail describe the registrable domain of the input and, if the chain ended on another one, that domain too.
Cookies are read from every hop.

If the HTTPS connection is refused, times out or fails the handshake, the response to the port 80 check, already in
flight, becomes the start of the chain at no extra request, and the report carries `sec.https.unavailable`. A response
that is not HTML skips the modules that read the page; a missing or generic content type is sniffed first, as browsers
do. A 4xx or 5xx status does not stop the run, but content modules are marked `partial`: an error page does not
represent the site.

## Connection engine

Each layer is opened by hand so each phase can be timed; hyper only parses HTTP over the socket insite provides, and no
ready-made client exposes these timings. The phases are DNS (to the first address), TCP, TLS (the handshake), TTFB and
download. TTFB ends when the response headers arrive, not at the first byte read, because the first bytes of an HTTP/2
connection can be control frames; that keeps the measure the same on both protocols.

A and AAAA go out in parallel, and connecting waits at most a further 50 ms for AAAA (the RFC 8305 resolution delay).
Attempts follow Happy Eyeballs: IPv6 first, alternating families, a new attempt every 250 ms or when one fails. If the
resolver finds nothing but the operating system does (a split-DNS VPN, mDNS), insite uses the system answer and marks
the DNS phase as not timed. A network failure before any HTTP response is retried once; an HTTP status never is. insite
follows redirects by hand, up to 10, reusing the connection when the next hop has the same origin. A loop or too many
hops becomes a finding, and the content modules report `failed`.

### TLS handshake

rustls with the `ring` provider, TLS 1.2 and 1.3, ALPN `h2` and `http/1.1`. A custom verifier runs the standard webpki
validation, records the result and lets the handshake finish, so a bad certificate becomes a finding instead of ending
the run. Trust roots are the embedded Mozilla set, so results do not depend on the machine; `--native-roots` uses the
system store. rustls does not speak TLS 1.0 or 1.1, RSA key exchange, DHE or CBC; a server that only offers those gives
`tls.handshake.incompatible`, and the analysis continues over port 80 if it serves content. HTTP/3 is not implemented
and shows up only as a technology, from `Alt-Svc`. When validation fails on an unknown issuer, insite looks up its
authority key identifier in an embedded CCADB list of public intermediates with their trust state. A trusted
intermediate the server did not send is `tls.chain.incomplete`: browsers that fetch it open the site, while curl and
most integrations fail. Revoked, distrusted, unknown and self-signed issuers get their own findings.

### Side requests

For an `https://` input without an explicit port, a plain HTTP request runs beside the page to see whether the site
forces HTTPS. `robots.txt` and `security.txt` start when the final headers arrive, while the body downloads, as extra
streams on the HTTP/2 connection or on a second connection for HTTP/1.1. The sitemap comes from the `Sitemap:` line of
`robots.txt`, or `/sitemap.xml`, and starts after the body so it does not compete with the download being timed. Many
servers answer 200 with an HTML page for any path, so each file is validated: `robots.txt` must be text with directives,
the sitemap a `urlset` or `sitemapindex`, and `security.txt` must have a `Contact` field.

insite caps the body at 5 MB on the wire and again after decompression (gzip, deflate, brotli), so a compression bomb
cannot exhaust memory; hitting the cap marks content modules `partial`. Proxies come from `HTTPS_PROXY`, `HTTP_PROXY`
and `NO_PROXY` through a CONNECT tunnel; the proxy resolves names, so the DNS phase is not timed.

## Signature engine

The HTML is extracted once, during analysis, from the body in the snapshot, so `--from` can re-extract with a newer
extractor. The charset comes from the byte order mark, then the `Content-Type` header, then a `<meta>` in the first 1024
bytes, then a valid-UTF-8 check, then windows-1252. lol_html tokenizes without building a DOM while one handler keeps a
stack of open elements, with the implied end tags that matter for descendant selectors, and records each element's tag,
attributes, parent and first 256 characters of text. That is enough for signature selectors and is not the HTML
tree-construction algorithm.

Detection uses the [webappanalyzer](https://github.com/enthec/webappanalyzer) signatures, pinned in
`crates/core/data/webappanalyzer/SOURCE.toml`, compiled at build time and matched behind a prefilter, so only the few
regexes that can match a page ever run.

### Build

`build.rs` calls `insite-sigc`, which writes `index.json` for the binary to embed. For each pattern string such as
`regex\;version:\1\;confidence:50` the compiler splits out the regex, the version template and the confidence, and
translates the regex from JavaScript to Rust syntax. Wappalyzer compiles every pattern case-insensitively, so insite
does too. Patterns that need lookaround or backreferences go to `fancy-regex`; the compiler drops anything neither
engine accepts and lists it in `sigc-report.txt`. It also extracts a required literal per pattern, its needle: prefixes
and suffixes from `regex-syntax`, and a literal in the middle (`wp-content/themes/` in `wp-content/themes/([^/]+)`) from
a short walk over the parsed regex. Needles under 3 bytes filter nothing, so those patterns, and those needing
`fancy-regex` or Unicode classes, are marked "always run". The compiler never compiles the `probe` field, because it
asks the server for specific paths.

### Matching

insite builds the engine on a background thread at t = 0, so it is ready before the page arrives. For each unkeyed field
(script sources, inline scripts, HTML, visible text, URL, `robots.txt`, certificate issuer) one Aho-Corasick automaton
scans the content once and returns the patterns whose needle appeared. Keyed fields (headers, cookies, meta, DNS
records, JavaScript properties) go straight to the patterns for their key. insite compiles only the candidate regexes,
on first use, and runs them. `fancy-regex` gets a backtracking limit of one million steps and at most 512 KB of input.
The engine sums confidence per technology and caps it at 100; below 100 a technology is reported as probable. It applies
`implies` recursively, `excludes` removes technologies, and `requires` and `requiresCategory` filter until the set is
stable, where one listed requirement is enough.

Every technology carries its evidence (field and matched text) and an `origin`: `page` for the page, headers, cookies,
scripts, URL, `robots.txt` or the browser; `dns` for DNS records alone; `certificate` for the issuer alone. The
strongest origin wins, and an implied technology inherits it. A Zoom verification TXT record shows that the company uses
Zoom and says nothing about how the page is built, and the origin keeps the two apart. The terminal shows the `page`
technologies as the stack and the `dns` ones on a `services` line; JSON keeps all of them.

### Data and updates

`data/` also holds `providers.toml` (NS, MX, ASN and CNAME evidence mapped to provider names, and bot-challenge
markers), `intermediates.tsv` (CCADB), `retire.tsv` (Retire.js vulnerable ranges, matched against detected library
versions) and `hsts-preload.tsv`. Each records its source and date, and the report lists them under `sources`.
`corrections.json` replaces a few webappanalyzer definitions that misfire on the hand-labeled sites (reasons in
`corrections.md`). `insite update` compiles newer webappanalyzer signatures into the cache directory; the engine uses
them if they are newer than the embedded ones and of the same index format. Corrections apply after the base, and the
user's own `fingerprints/*.json` after them, both by technology name.

## Analyzers

Each analyzer reads the snapshot and returns a status, typed data and findings. Provider names come from
`providers.toml`; with no match the report shows the raw NS, MX or AS name instead of guessing.

### Security

The grade follows the [MDN HTTP Observatory](https://github.com/mdn/mdn-http-observatory) at a pinned commit. The code
reproduces its twelve tests and score modifiers, quirks included ("six months" is 180 days), and the embedded HSTS
preload list lets the HSTS test treat preloaded hosts as the Observatory does. Mixed content, forms posting over HTTP,
version leaks, `Permissions-Policy` and an expired `security.txt` are findings outside the methodology and leave the
grade alone. The grade is withheld, and the module is `partial`, when the response does not represent the site (a bot
challenge or an error status). The one known gap is the CORS test's -50 case, which needs a request with a foreign
`Origin`.

### TLS

Validity, hostname coverage, issuer, key, signature algorithm, negotiated version and suite, and the chain diagnosis
above. `tls.cert.expiring` fires when fewer days remain than the smaller of 14 days and a quarter of the certificate's
lifetime, so it works the same for one-year and 45-day certificates. Days count from `collected_at`, and a server `Date`
header more than 5 minutes off the local clock raises `tls.clock_skew`.

### DNS and e-mail

A, AAAA and CNAME on the host; CAA from the host up to the registrable domain, as a certificate authority looks it up;
NS, MX, TXT, SOA and DS on the registrable domain; `_dmarc` on the host and then the registrable domain; and the TXT
records for MTA-STS, TLS-RPT and BIMI (`_mta-sts`, `_smtp._tls`, `default._bimi`). All queries run in parallel. insite
counts SPF lookups against the limit of 10, which means resolving includes and redirects in rounds after the first
queries, within a 2 s budget. DKIM cannot be checked without the selector, so insite tries five common ones; if none
answers, DKIM is "not determined", never "absent". A resolver that returns no NS for a domain whose host resolves is
filtering queries, and the module then does not read its empty answers as missing records.

Some home routers and ISP modems drop large UDP answers, refuse DNS over TCP or reject DS queries. So when the system
resolver fails on a query, or is silent for 500 ms, insite asks the zone's own name servers as well, and the first valid
answer wins. The zone is the closest name with NS records, since delegated subzones have servers of their own; to find
it, the system resolver races iterative resolution from the 13 IANA root servers (the hickory `Recursor`). It asks up to
three servers, without recursion, over UDP and then TCP if the answer is truncated. Only public addresses are queried,
because a zone's NS can name a host inside the network of whoever runs insite.

### Infrastructure

Two DNS queries to Team Cymru's IP-to-ASN service give the AS, prefix and owner, which identify hosting; a CDN or WAF is
recognized from headers, `Server`, CNAMEs and the AS. A bot challenge (Cloudflare, Akamai and others) is recognized from
status, headers and markers in the first 64 KB of the body; the report is then partial and no stack is inferred from the
challenge page.

### SEO and weight

SEO covers metadata, canonical, robots directives, headings, structured data, `robots.txt` and the sitemap. Weight
covers HTML size and compression, render-blocking scripts, images and third-party domains. Resource sizes come only from
`--browser`; fetching them without one would multiply the requests.

## Browser mode

`--browser` drives headless Chrome, Chromium, Edge or Brave through the DevTools Protocol, with a client of about twenty
commands in `collect/browser/cdp.rs` and no Node or Lighthouse; a generated protocol crate would add thousands of types
for a small slice of the protocol. On Linux and macOS the transport is `--remote-debugging-pipe`: NUL-terminated JSON
over file descriptors 3 and 4, with no port and no WebSocket. On other platforms the browser module reports that it is
not available.

The process starts at t = 0 beside the fast collection, but navigation begins only once the main body is complete, so
the browser never competes for bandwidth with the timings insite is measuring. The emulation is a phone, or a desktop
with `--desktop`; `--throttle` applies Lighthouse's mobile Slow 4G and 4x CPU values for its devtools method, since its
default simulated mode is not comparable. A script injected before load records LCP, CLS, FCP and long tasks, from which
TBT is computed. The page is read once it has loaded, painted and had at most two requests in flight for one second, or
15 s after `load` for pages that never settle, which marks the module `partial`. One `Runtime.evaluate` returns the
metrics and the JavaScript and element properties the signatures ask for, and the rendered HTML goes into the snapshot.
Analysis then runs the signatures again over it. If both passes end on the same URL the results merge and the browser's
version wins; if the browser ended elsewhere, such as an `m.` site, the report shows both stacks. Every metric carries
its profile, because an unthrottled LCP is not the PageSpeed one, and insite uses no field data.

## Scheduler, deadlines and exit codes

Whatever depends on nothing starts at t = 0, and each task waits only for what it needs. Host resolution, the DNS
records of the input domain, the port 80 check and the browser process start at once. The page request follows the first
address, `robots.txt` and `security.txt` follow the final headers, the sitemap and the browser navigation follow the
complete body, and the final domain's records and the AS lookup wait for the chain. Analysis starts when the snapshot
closes or the deadline expires.

With `-m`, only the collection those modules need runs; the rest are `skipped`. The fast collection has a 5 s deadline
(`--timeout`), also with `--browser`. The browser has 20 s, or 60 s with `--throttle`, counted from when its slot
starts. Inside that, DNS gets 2 s, TCP 3 s and TLS 3 s, so one stuck step cannot spend the whole deadline. When the
deadline passes, insite cancels pending tasks and builds the report from what arrived. The first Ctrl-C does the same
early; the second quits at once, killing browsers and deleting their profiles first. The runtime is tokio with four
workers, and analysis runs on `spawn_blocking` so CPU work does not hold up the I/O of other sites in a batch.

A module's status is `ok`, `partial`, `timeout`, `failed` or `skipped`, with a reason when it is not `ok`. Failures are
typed by `FailureKind` (DNS, connect, TLS, HTTP, redirect loop, too many redirects, timeout, proxy). The exit codes are
in [usage.md](https://github.com/jospnunes/insite/blob/main/docs/usage.md#exit-codes). A minor `partial`, such as a
sitemap read only up to 1 MB, keeps the code at 0 rather than 3; otherwise 3 would become the normal result and scripts
could not rely on it.

In a batch the most serious code wins, and up to 8 sites run at once (`--concurrency`). Analyses of the same registrable
domain run one after another with a one-second pause, so a host never sees more than one at a time. With `--browser`, at
most two browsers run at once.

## Data model and JSON stability

`Snapshot` holds observations and no conclusions: the request headers sent, the hop chain with timings, retries,
connection details and certificates, the decoded body, the port 80 check, DNS answers, the AS lookup, helper files and
browser data, plus its version and `collected_at`. It does not store `PageFacts`, which is derived from the body.
`--save` writes one snapshot per line, gzipped if the name ends in `.gz`. `--from` accepts only the snapshot version the
binary writes; only one version exists, so there is no conversion code yet.

`Report` holds `schema_version`, collector and analyzer versions, the target, `started_at`, duration, an `outcome`
(`complete`, `partial` with reasons, or `unreachable`), the data `sources` with versions, and nine modules, each a
`Module<T>` with `status`, `reason`, `data` and `findings`. A `Finding` has a stable `id` such as `sec.hsts.missing`, a
severity from `info` to `critical`, `params` with structured values, `evidence` with the data that produced it, and a
title, detail and fix. The constructor requires an evidence string, so no finding can exist without evidence. Texts come
from one catalog, `crates/core/findings/<id>.md`, embedded in the binary and used by `insite explain`. They are English
and may change; consumers should key on `id` and `params`. `schema_version` follows semver: a new field raises the minor
version, a removal or type change the major one.

## Output

The formats are the text view (default), `--json` (an array for several sites), `--ndjson` (one report per line; with
`--browser`, two per site, `phase` `fast` then `full`) and `--md`. On an interactive terminal the text view is animated:
phases fill as bars, redirects appear as they are followed, each module spins until its data arrives, and a batch
becomes a table. `live_mode` in `crates/cli/src/main.rs` decides when this happens, and takes its inputs as parameters
so tests do not touch the environment.

The collector reports progress through an optional unbounded channel (`insite_core::collect::progress`): `Phase` for a
finished request phase, `Redirect` for a followed redirect, `Done` when a part of the collection settles (also when it
is skipped, so no row waits for something that will not run) and `Browser` for the stages of the visit. With no channel
nothing is built or sent, and a failed send is ignored, so the interface never holds up collection. The analysis never
sees these events. The renderer in `crates/cli/src/live/` has one thread that owns the terminal and redraws one live
region; the files that build each view return lines and never touch the terminal. Text controlled by the page passes
through `style::neutralize` before it gets color, so a hostile escape sequence cannot reach the terminal. The final
frame is a pure function of the `Report`, so `--from` on a terminal shows it without animation.

## Dependencies

There are 28 direct runtime dependencies. `ring` enters as a feature of rustls.

| Crate | Used for | Why a crate |
| --- | --- | --- |
| tokio | async runtime | the runtime that tokio-rustls, hickory and hyper-util plug into |
| rustls, tokio-rustls, webpki-roots, rustls-native-certs | TLS and trust roots | cryptography is not written by hand; `ring` over `aws-lc-rs` because it builds without CMake on musl and Windows |
| hickory-resolver | DNS queries, iterative resolution (`recursor`) | speaks the DNS protocol and exposes the timings and records insite needs |
| hyper, hyper-util, http, http-body-util | HTTP/1.1 and HTTP/2 over insite's socket | HTTP/2 with HPACK is large and not where insite differs |
| url, idna, psl, encoding\_rs | URLs, international names, registrable domains, charsets | WHATWG rules and the Mozilla suffix list, full of edge cases |
| flate2, brotli-decompressor, x509-parser | decompression, certificates | closed formats; only the decoders are needed |
| lol\_html | HTML tokenizer | streams the HTML without building a DOM |
| regex, regex-syntax, aho-corasick, fancy-regex | matching, literal extraction, multi-pattern search | `regex` runs in linear time; `fancy-regex` only for lookaround and backreferences |
| serde, serde\_json, toml | JSON reports and snapshots, `providers.toml` | serialization |
| clap, crossterm | arguments and help; terminal width, cursor and Windows console mode | command-line parsing and platform differences |
| libc (Unix) | `geteuid`, descriptors for the browser pipe | system calls the standard library lacks |

Left out on purpose: `reqwest`, which hides per-phase timings and decides redirects itself; `scraper` and `html5ever`,
which build a full DOM when only an element index is needed; `chromiumoxide`, which generates the whole protocol; and
`anyhow` and `thiserror`, which a typed failure enum makes unnecessary.

## Testing

Collection and analysis are separate, so most tests need no network: `crates/core/tests` runs local HTTPS servers with
generated certificates and a local DNS server, and a determinism test requires identical JSON from one snapshot analyzed
twice and again after a `--save` and `--from` round trip. Two tests read recorded real pages, which hold third-party
HTML and so live in the private repository `jospnunes/insite-fixtures`; without its key, as in pull requests from forks,
they pass without running. `labeled` checks every detection on 20 sites against the verdicts in `bench/labels.tsv` and
requires a precision of at least 0.95. `conformance` runs the Wappalyzer JavaScript core in Node
(`scripts/conformance/`) over the same inputs and signatures and requires an F1 of at least 0.90. Both use the reference
list, `bench/sites.tsv`: 100 sites, half Brazilian and half international, ten of them hard cases (bot challenges,
incomplete chains, legacy TLS). [methodology.md](https://github.com/jospnunes/insite/blob/main/docs/methodology.md)
describes the measurements.

## Known limits

- Analysis overhead is a median of 130 ms on the measurement VPS, above the 50 ms target
  ([methodology.md](https://github.com/jospnunes/insite/blob/main/docs/methodology.md#timing)).
- `--browser` does not run on Windows, and the Windows console output has not been checked by hand.
- insite follows redirects, and the `Sitemap:` URL in `robots.txt`, to whatever address they name, private addresses
  included, so it should not be pointed at untrusted targets from a sensitive network.
- The security grade does not reproduce the Observatory's CORS -50 case.
- Sites that challenge clients that are not browsers give a partial report (exit code 3). The default User-Agent is
  `insite/<version>`; `--ua hybrid` and `--ua chrome` change it.

- There is no published JSON Schema, and the parsers that read untrusted input are not fuzzed.
