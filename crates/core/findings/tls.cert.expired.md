severity: critical
title: Certificate expired
---
The certificate expired on {date}, {days} days ago. Browsers show a full-page warning and most visitors leave; APIs and integrations refuse to connect.

## Fix
Renew the certificate and install it on every server and CDN that answers for this name. With Let's Encrypt or any ACME client, check that automatic renewal is running and that the web server reloads after it.
