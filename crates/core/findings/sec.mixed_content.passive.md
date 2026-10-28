severity: low
title: {count} images over HTTP on an HTTPS page
---
The HTTPS page loads images over plain HTTP. Browsers upgrade or block them and may mark the page as not fully secure.

## Fix
Change the image addresses to `https://` (or relative ones).
