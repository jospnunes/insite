severity: high
title: Certificate does not cover {host}
---
The certificate is valid for {names}, but not for {host}. Browsers show a warning for this address.

## Fix
Issue a certificate that includes {host} among its names (or a wildcard that covers it), or redirect this address to a name the certificate covers before any content is served.
