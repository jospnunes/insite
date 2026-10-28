severity: low
title: HSTS max-age is shorter than six months
---
The HSTS policy ({value}) lasts less than six months, so browsers that have not visited recently fall back to plain HTTP on the first request.

## Fix
Raise `max-age` to at least 15552000 (180 days); a year (31536000) is common.
