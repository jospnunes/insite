severity: medium
title: Content Security Policy allows scripts or styles over HTTP
---
The HTTPS page's policy allows active content (scripts, styles, frames) from `http:` or `ftp:` sources, which an attacker on the network can alter. Policy: `{value}`.

## Fix
Replace `http://` sources with their `https://` versions and remove `http:` and `ftp:` from the policy.
