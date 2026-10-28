severity: info
title: {provider} answered with a bot challenge
---
Instead of the page, {provider} served a challenge or block page meant to stop automated clients. Everything that depends on the page content (stack, SEO, weight, security grade) is partial and nothing is concluded from the challenge page itself.

## Fix
Nothing to fix on the site. Run insite with `--browser`, which loads the page in a real browser and usually passes the challenge.
