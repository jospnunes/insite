severity: low
title: HTTP redirects to another HTTP address before HTTPS
---
The first redirect from the plain HTTP address goes to another `http://` address before reaching HTTPS, so that extra step is unencrypted, and HSTS for the original host is never set. Route: {value}.

## Fix
Redirect from `http://` straight to `https://` on the same host first, then to the canonical address (`www` or not).
