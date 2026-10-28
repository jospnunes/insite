severity: medium
title: HTTP does not redirect to HTTPS
---
The site answers on plain HTTP without redirecting to HTTPS, so visitors who type the address or follow an old `http://` link stay on an unencrypted connection. Route: {value}.

## Fix
Redirect every `http://` request to the same address over `https://` with a 301, then enable HSTS so browsers go straight to HTTPS.
