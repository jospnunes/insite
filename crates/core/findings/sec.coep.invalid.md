severity: low
title: Cross-Origin-Embedder-Policy has an invalid value
---
The `Cross-Origin-Embedder-Policy` header ({value}) does not parse or is not `require-corp`, `credentialless` or `unsafe-none` (values are case-sensitive), so browsers ignore it.

## Fix
Send the header once with one of the valid values, in lowercase.
