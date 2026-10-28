severity: medium
title: Certificate expires in {days} days
---
The certificate expires on {date}, and less than a quarter of its validity (or 14 days) is left. Certificates are normally renewed well before this point, so the renewal may be failing.

## Fix
Check the renewal job (certbot, the ACME client or the hosting panel) and its logs, renew now, and make sure the web server reloads the new certificate.
