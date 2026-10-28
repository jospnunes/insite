severity: medium
title: Too many redirects
---
The chain went past {max} redirects without reaching a page. Every extra hop costs a round trip, and browsers stop at around 20.

## Fix
Point each old address directly at the final URL instead of chaining redirects, so a visitor needs at most one hop.
