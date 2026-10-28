severity: medium
title: Invalid certificate on {host}
---
The redirect chain passes through {host}, whose certificate is invalid: {problem}. Visitors who type that address see a browser warning before reaching the redirect.

## Fix
Install a valid certificate on {host} too, since browsers check it before following the redirect.
