# Changelog

## 0.1.0 - 2026-10-30

First release. insite is a command-line tool that gives a full X-ray of a website in about a second, from a single binary: network, TLS, DNS and e-mail, infrastructure, technology stack, security grade, technical SEO and page weight. It is passive: it reads what any visitor would see.

### Highlights

- Modules: network timings per phase, TLS (certificate, chain, expiry), DNS and e-mail (SPF, DMARC, DKIM, MTA-STS), infrastructure (AS, hosting, CDN), stack detection, security grade, SEO and page weight.
- Stack detection uses the webappanalyzer signatures (about 7,600 technologies), and every finding shows the evidence behind it.
- Security grade from A+ to F, following the MDN HTTP Observatory scoring.
- `--browser` adds Core Web Vitals and the stack only JavaScript reveals; `--throttle` makes them comparable to Lighthouse mobile.
- Output: terminal, `--json`, `--ndjson`, `--md`.
- Live terminal output: on an interactive terminal the analysis is drawn as it happens (request phases as bars, modules settling one by one, the browser step and the batch table), and the final screen stays in the scrollback. It turns itself off for pipes and files, `--json`, `--ndjson`, `--md`, `NO_COLOR` and `TERM=dumb`, where the output is the same plain text as before.
- Batch mode: several sites as arguments or on standard input.
- The port 80 redirect route (the HTTP-to-HTTPS check) is now followed in parallel with the page, so it no longer waits for the main request.
- `--save` and `--from` store and re-analyze snapshots without network.
- `insite explain <id>` describes a finding and how to fix it; `insite update` fetches the newest signatures; your own signatures can be added.

### Measured

- Speed: p50 total time of 888 ms over the 100-site reference list (1028 ms without the 10 hard cases), run one site at a time from a VPS in Boston. Brazilian sites are slower from there (1424 ms).
- Precision: 0.995 on 20 hand-labeled sites (410 correct, 2 wrong, 17 uncertain).
- Agreement: F1 0.997 against the Wappalyzer JavaScript core on 90 sites.

### Known limits

- Analysis overhead is a median of 130 ms on that VPS (60 to 100 ms on a laptop), above the 50 ms target. Accepted for now.
- `--browser` does not run on Windows yet; the browser module reports that it is not available on this platform.
- On the Windows console, colours and width go through crossterm and have not been checked by hand; set `NO_COLOR` for plain text.
- The security grade does not reproduce the Observatory's CORS -50 case, which needs a cross-origin request.
- Sites that challenge non-browser clients give a partial report (exit code 3).
- No published JSON Schema yet; key on finding `id` and `params`.
- Binaries are unsigned: Windows SmartScreen warns on a downloaded binary.
- No AUR, Homebrew or Scoop packages yet.
