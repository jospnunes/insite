# Contributing

Thank you for helping. A few rules keep insite trustworthy:

- **No finding without evidence.** Every finding carries the observed data
  that produced it, and an absence is only reported when it was measured: a
  failed query, a filtering resolver or a bot challenge is reported as such.
- **Analysis is pure.** Analyzers read a `Snapshot` and never touch the
  network or the clock (`collected_at` is "now"). The same snapshot must give
  the same report, byte for byte.
- **Findings live in the catalog.** Each id has a file in
  `crates/core/findings/<id>.md` (severity, title, detail and fix) and an entry
  in `findings.rs`; ids are stable once released.
- **Tests use synthetic fixtures** (local servers in `crates/core/tests`), never
  recordings of real sites.

Before sending a change:

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

Browser tests run when `CHROME_PATH` points to Chrome or Chromium.

Embedded data is regenerated with the scripts in `scripts/` (Python standard
library only); new signatures belong upstream in
[webappanalyzer](https://github.com/enthec/webappanalyzer).

By contributing you agree that your work is licensed under GPL-3.0-or-later.
