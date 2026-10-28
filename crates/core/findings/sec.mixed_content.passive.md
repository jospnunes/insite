severity: low
title: Images over HTTP on an HTTPS page ({count})
---
The HTTPS page loads images over plain HTTP. Browsers upgrade or block them and may mark the page as not fully secure.

## Fix
Change the image addresses to `https://` (or relative ones).
