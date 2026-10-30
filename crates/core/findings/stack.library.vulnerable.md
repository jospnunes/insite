severity: medium
title: {library} {version} has known vulnerabilities
---
The page uses {library} {version}, which the Retire.js database lists with known vulnerabilities (known issues in this version: {count}, highest severity: {severity}). Most serious: {summary}. Identifiers: {ids}. Flaws in front-end libraries often let an attacker run script in a visitor's browser, for example through cross-site scripting. Retire.js matches by version number, so a build with the fix backported (some CMS and distribution packages do this) can be flagged too.

## Fix
Update {library} to {fixed} or later, which clears every issue listed for this version. If the library comes with a theme, plugin or CMS, update that instead, and check that the page still works. Where an update is impossible, limit what the page does with untrusted input and add a Content-Security-Policy.
