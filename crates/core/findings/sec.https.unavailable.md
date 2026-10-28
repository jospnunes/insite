severity: high
title: HTTPS does not work
---
The site could not be reached over HTTPS ({reason}), so the page was read over plain HTTP. Everything visitors send and receive can be read and changed by anyone on the network, and browsers mark the site as not secure.

## Fix
Install a certificate (Let's Encrypt is free and most hosts enable it with one click), serve the site on port 443, then redirect HTTP to HTTPS.
