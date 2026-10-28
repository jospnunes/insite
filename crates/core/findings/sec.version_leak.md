severity: low
title: Server software version exposed
---
The `{header}` header reveals software and version (`{value}`), which helps an attacker match the server to known vulnerabilities.

## Fix
Hide versions in the server configuration (for example `server_tokens off;` in nginx, `ServerTokens Prod` in Apache, `expose_php = Off` in PHP), and keep the software up to date regardless.
