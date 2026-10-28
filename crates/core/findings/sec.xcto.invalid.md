severity: low
title: X-Content-Type-Options has an invalid value
---
The `X-Content-Type-Options` header ({value}) is not `nosniff`, the only value browsers recognize, so it has no effect.

## Fix
Send exactly `X-Content-Type-Options: nosniff`.
