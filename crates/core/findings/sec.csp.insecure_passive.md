severity: low
title: Content Security Policy allows images or media over HTTP
---
The HTTPS page's policy allows images or media from `http:` sources. A network attacker can replace them, and browsers flag the page as not fully secure.

## Fix
Serve images and media over HTTPS and remove `http:` from `img-src` and `media-src`.
