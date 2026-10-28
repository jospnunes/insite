severity: medium
title: X-Frame-Options has an invalid value
---
The `X-Frame-Options` header ({value}) has no value browsers recognize, so the page is not protected against clickjacking.

## Fix
Use `X-Frame-Options: SAMEORIGIN` or `DENY`, or better, `Content-Security-Policy: frame-ancestors 'self'`.
