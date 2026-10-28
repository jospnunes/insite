severity: high
title: Weak certificate key ({key})
---
The certificate uses a {key}-bit key, below the minimum that certificate authorities and browsers accept today (RSA 2048, ECDSA P-256).

## Fix
Generate a new key (ECDSA P-256 or RSA 2048 or larger) and reissue the certificate with it.
