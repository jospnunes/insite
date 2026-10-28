severity: medium
title: Cookies without the Secure flag
---
Cookies ({value}) are set without `Secure` and the site has no long-lived HSTS, so the browser may send them over plain HTTP, where they can be read or changed.

## Fix
Add `Secure` to every cookie set by an HTTPS site, and enable HSTS.
