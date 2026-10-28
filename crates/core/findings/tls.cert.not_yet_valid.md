severity: high
title: Certificate not valid yet
---
The certificate only becomes valid on {date}. Until then browsers reject it. This usually means the certificate was issued with a wrong date or the server clock is far off.

## Fix
Check the server clock (NTP) and the validity dates of the installed certificate; reissue it if the dates are wrong.
