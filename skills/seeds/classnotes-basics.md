---
# bughive-repro-start
cve: null
repro: unverified
# bughive-repro-end
---

# SKILL: classnotes-basics
## HTTP Methods
- GET: params in URL, cached
- POST: params in body
- PUT: store/modify — dangerous if unauth
- DELETE: destroy — dangerous if unauth
- OPTIONS: introspect allowed methods
## Test
OPTIONS / HTTP/1.1
PUT /1.txt HTTP/1.1
DELETE /1.txt HTTP/1.1
_method=PUT / _method=DELETE
## Triage
Unauth PUT → High/Critical. Unauth DELETE → Critical.

<!-- bughive-repro-start -->
## Steps to reproduce

> Status: `repro: unverified` — no CVE was resolved for this skill. Nothing below was invented.

### What's missing
- no CVE/target in skill; needs teardown or stays unverified
<!-- bughive-repro-end -->
