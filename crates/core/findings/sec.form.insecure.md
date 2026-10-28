severity: medium
title: A form sends data over plain HTTP
---
A form on this HTTPS page submits to an `http://` address ({action}), so what visitors type is sent unencrypted. Browsers warn before submitting it.

## Fix
Change the form's `action` to an `https://` (or relative) address.
