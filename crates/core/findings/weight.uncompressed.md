severity: medium
title: HTML served without compression ({size})
---
The page HTML ({size}) is sent without gzip, brotli or zstd. Text compresses to about a fifth of its size, so every visit downloads several times more than needed.

## Fix
Enable compression for text types (HTML, CSS, JavaScript, JSON, SVG) on the server or CDN: `gzip on;` or the brotli module in nginx, mod_deflate in Apache.
