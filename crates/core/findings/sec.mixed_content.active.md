severity: medium
title: {count} scripts, stylesheets or frames over HTTP on an HTTPS page
---
The HTTPS page loads active content over plain HTTP. Browsers block it, so those parts of the page probably do not work, and where they are not blocked an attacker on the network could alter them.

## Fix
Load these resources over `https://`. If a host does not support HTTPS, move the file elsewhere or host it yourself.
