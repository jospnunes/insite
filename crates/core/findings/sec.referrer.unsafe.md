severity: low
title: Referrer-Policy sends full addresses to other sites
---
The `Referrer-Policy` ({value}) lets the browser send the full page address, or the origin over plain HTTP, to other sites. Addresses can carry private information such as search terms or tokens.

## Fix
Use `Referrer-Policy: strict-origin-when-cross-origin` (the browser default) or something stricter, like `same-origin` or `no-referrer`.
