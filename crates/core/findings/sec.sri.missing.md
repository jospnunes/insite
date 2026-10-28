severity: low
title: Scripts from other domains without Subresource Integrity
---
The page loads scripts from other domains ({value}) without an `integrity` attribute. If that host or CDN is compromised, the altered script runs on this page with full access.

## Fix
Add `integrity="sha384-…"` and `crossorigin="anonymous"` to scripts from CDNs with fixed versions, or host the files yourself. Scripts that change constantly (analytics, tag managers) cannot use SRI; keep that list short.
