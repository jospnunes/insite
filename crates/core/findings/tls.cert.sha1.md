severity: high
title: SHA-1 signature in the chain
---
{subject} is signed with SHA-1, which every current browser rejects because collisions are practical.

## Fix
Reissue the certificate, or install the current intermediate from your certificate authority, signed with SHA-256 or stronger.
