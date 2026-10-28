severity: info
title: No Permissions-Policy
---
The page sends no `Permissions-Policy` header. It is optional, but it lets the site switch off browser features it does not use (camera, microphone, geolocation, payment) for itself and for embedded frames, which limits what a compromised third-party script can do.

## Fix
Disable what the site does not use, for example `Permissions-Policy: camera=(), microphone=(), geolocation=()`.
