severity: medium
title: No HSTS
---
The HTTPS page has no `Strict-Transport-Security` header. Without it, a visitor who types the address or follows an `http://` link starts on plain HTTP, where an attacker on the network can intercept the redirect.

## Fix
Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` from the HTTPS site (after checking every subdomain supports HTTPS). Start with a short max-age if unsure, then raise it.
