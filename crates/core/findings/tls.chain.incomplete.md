severity: medium
title: Incomplete certificate chain
---
The server does not send the intermediate certificate {missing} ({owner}). Browsers that fetch missing intermediates open the site, but curl, mobile apps, payment and webhook integrations fail with a certificate error.

## Fix
Configure the server with the full chain file (often called fullchain.pem), not just the site certificate. In nginx, `ssl_certificate` must point to the full chain.
