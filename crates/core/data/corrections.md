# Signature corrections

`corrections.json` replaces webappanalyzer technologies that misfire, by name,
on top of whichever base is in use (embedded or from `insite update`). Each
entry is the upstream definition with one change. They were found on the
hand-labeled sites (`bench/labels.tsv`, 2026-10-29) and should go once upstream
fixes them.

| Technology | Change | Why |
| --- | --- | --- |
| Apple iCloud Mail | TXT `apple-domain` becomes `^apple-domain=` | `apple-domain-verification=` is Apple Business or Apple Pay domain verification, present on domains whose mail is elsewhere |
| Cart Functionality | `a[href*='/cart']` becomes `/cart` at the end of the path or before `/`, `?`, `#`; the URL pattern ends the same way | matched Portuguese words: cartão, carteira, carta, Cartola |
| PHP | drops the `scripts` pattern `\.php(?:\?\|$)` | any inline script that mentions a `.php?` URL of a third party (VWO, share links) matched |
| cdnjs | drops `implies: Cloudflare` | cdnjs is hosted by Cloudflare; a site that loads from it is not behind Cloudflare |
| Google Tag Manager | drops the scriptSrc `\.googletagmanager\.com/` | `gtag/js?id=G-…` is Google Analytics 4, not a GTM container |
| DoubleClick Floodlight | scriptSrc `\.doubleclick\.net` becomes `fls\.doubleclick\.net` | matched Google Publisher Tag (`securepubads.g.doubleclick.net`) |
| YUI Doc | drops the `yui3-skin-sam` body class | that is the YUI 3 skin class, used by the library (Liferay pages), not the documentation generator |
| Lightbox | scriptSrc must be a file named `lightbox[-plus-jquery][.min].js` | matched other libraries with lightbox in the path (`gui.lightbox.min.js`) |
| Aprimo | `img[src*='aprimo']` becomes `img[src*='.aprimo.com/']` | matched the Portuguese word "aprimora" in an image URL |
