severity: high
title: A redirect leaves HTTPS for HTTP
---
The redirect chain goes from HTTPS to plain HTTP ({from} → {to}). Visitors who started on a secure connection end up on an insecure one, and anything that follows, cookies included, travels unencrypted.

## Fix
Make every redirect point to an `https://` address. Check the server and application settings that build redirect URLs, and any proxy in front that might rewrite the scheme.
