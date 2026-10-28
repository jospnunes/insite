severity: low
title: No X-Content-Type-Options
---
The response has no `X-Content-Type-Options: nosniff`, so browsers may guess a file's type from its content and, for example, run a user-uploaded file as a script or stylesheet.

## Fix
Send `X-Content-Type-Options: nosniff` on every response, and make sure each file is served with its correct `Content-Type`.
