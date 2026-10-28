severity: medium
title: Cookie with an invalid SameSite value
---
A cookie ({value}) has a `SameSite` attribute with no value or an unknown one, or uses `SameSite=None` without `Secure`, which browsers reject. The protection the attribute was meant to give is not there.

## Fix
Use `SameSite=Lax`, `SameSite=Strict`, or `SameSite=None; Secure` for cookies that really must be sent cross-site.
