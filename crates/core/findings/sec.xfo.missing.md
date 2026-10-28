severity: medium
title: Page can be framed by any site (clickjacking)
---
There is neither `X-Frame-Options` nor a CSP `frame-ancestors` directive, so any site can show this page inside a frame and trick visitors into clicking on it.

## Fix
Send `Content-Security-Policy: frame-ancestors 'self'` (or `'none'`), or `X-Frame-Options: SAMEORIGIN` for older browsers. List specific hosts only if the page really must be embedded elsewhere.
