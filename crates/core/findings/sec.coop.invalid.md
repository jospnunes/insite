severity: low
title: Cross-Origin-Opener-Policy has an invalid value
---
The `Cross-Origin-Opener-Policy` header ({value}) does not parse or is not one of `same-origin`, `same-origin-allow-popups`, `noopener-allow-popups` or `unsafe-none` (values are case-sensitive), so browsers ignore it.

## Fix
Send the header once with one of the valid values, in lowercase; `same-origin` gives the most isolation.
