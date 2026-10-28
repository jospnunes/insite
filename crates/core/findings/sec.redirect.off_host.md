severity: low
title: HTTP redirects to HTTPS on another host
---
The first redirect from the plain HTTP address goes to HTTPS on another host, so the browser never sees an HTTPS response (and HSTS) for the original host. Route: {value}.

## Fix
Redirect `http://host/` to `https://host/` first (setting HSTS there), then to the other host.
