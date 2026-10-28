severity: medium
title: Scripts from other domains loaded insecurely
---
The page loads scripts from other domains over plain HTTP or with protocol-relative addresses (`//host/…`), which the methodology counts as insecure: {value}.

## Fix
Load every external script with an explicit `https://` address, and add `integrity` to those with fixed versions.
