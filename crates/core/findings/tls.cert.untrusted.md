severity: high
title: Certificate not trusted
---
Browsers do not trust this certificate: {reason}.

## Fix
Install a certificate from a publicly trusted certificate authority with its full chain. If this result comes from a corporate network that inspects TLS, run insite with `--native-roots` to validate against the system trust store instead.
