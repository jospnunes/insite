severity: medium
title: HSTS header is invalid
---
The `Strict-Transport-Security` header ({value}) has no valid `max-age`, or is sent more than once, so browsers may ignore it.

## Fix
Send the header once, as `Strict-Transport-Security: max-age=31536000; includeSubDomains`.
