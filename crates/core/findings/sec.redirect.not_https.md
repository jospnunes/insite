severity: medium
title: HTTP redirects, but never reaches HTTPS
---
The plain HTTP address redirects, but the visitor ends up on another `http://` address. Route: {value}.

## Fix
Make the first redirect from HTTP go to the `https://` address, and keep every later step on HTTPS.
