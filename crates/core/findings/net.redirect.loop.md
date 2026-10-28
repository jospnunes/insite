severity: high
title: Redirect loop
---
The redirect chain comes back to {url}, which it had already visited. Browsers give up with an error, so visitors and search engines never reach a page.

## Fix
Review the redirect rules on the server, CDN and application together: a common cause is one layer forcing `www` or HTTPS while another forces the opposite. Each URL should redirect at most once, straight to the final address.
