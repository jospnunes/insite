severity: info
title: Clock differs from the server by {minutes} minutes
---
The server's `Date` header differs from this machine's clock by about {minutes} minutes. Day counts for certificate expiry are computed from this machine's clock, so they may be off by that much; either clock may be the wrong one.

## Fix
Check that this machine and the server both synchronize time with NTP.
