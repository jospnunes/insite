severity: low
title: TLS 1.3 not supported
---
The server negotiated TLS 1.2 although TLS 1.3 was offered. TLS 1.3 needs one round trip fewer to connect and removes legacy options.

## Fix
Enable TLS 1.3 in the web server or CDN (for nginx, `ssl_protocols TLSv1.2 TLSv1.3;` with OpenSSL 1.1.1 or later).
