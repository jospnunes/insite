severity: low
title: Cookies without the Secure flag (HSTS mitigates)
---
Cookies ({value}) are set without `Secure`. HSTS keeps the browser on HTTPS for this host, which limits the risk.

## Fix
Add `Secure` to every cookie set by an HTTPS site.
