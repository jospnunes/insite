# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately, not in a public issue. On the
repository page [jospnunes/insite](https://github.com/jospnunes/insite), open
the **Security** tab and choose **Report a vulnerability**. That opens a private
security advisory that only the maintainer can read.

Include the insite version (`insite --version`), the command you ran and, if
you can, a minimal page or response that reproduces the problem.

## What counts

insite analyzes sites it does not control, so the web page, its headers, DNS
answers and certificates are all untrusted input. These count as security
issues:

- a panic or crash in a parser (HTML, headers, robots.txt, sitemap, DNS,
  certificates) caused by a hostile site;
- terminal escape injection: text from a site that reaches the terminal as
  control or escape sequences;
- resource exhaustion (memory, CPU, time, open connections) caused by a
  hostile site, beyond the documented limits and deadlines.

Following redirects and `Sitemap:` URLs to private addresses is known and
documented in the README; it is not treated as a vulnerability.

## Supported versions

Only the latest release gets fixes.
