severity: high
title: Self-signed certificate
---
The certificate was signed by itself, not by a certificate authority. Browsers and HTTP clients do not trust it.

## Fix
Replace it with a certificate from a public certificate authority. Let's Encrypt issues them for free and can renew them automatically.
