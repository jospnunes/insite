severity: critical
title: SPF of {domain} authorizes the whole internet
---
The SPF record of {domain} ends in `+all`, which tells receivers that any server in the world may send mail as {domain}.

## Fix
End the record in `-all` (or `~all` while testing) after listing the services that really send mail for the domain.
