---
repro: technique-authored
---

# SKILL: open-redirect
## Params
?redirect_url= ?next= ?continue= ?goto= ?return_Url= ?destination= ?fromURI= ?redirect= ?go= ?from= ?return= ?rurl= ?checkout_url=
## Payloads
?next=https://evil.com
?next=//evil.com
?next=https://target.com@evil.com/d
?next=https://target.com.evil.com/d
?next=°/https://evil.com
?next=javascript:alert(document.domain)
## Hunt
Dorks: inurl:"?next=" site:target.com
Spider: =http, =/, =%2F, =aHR
Path fragment: target.com//evil.com, target.com/.evil.com
## Triage
Reflected → Low. Whitelist bypass → Med. → ATO/XSS → High.

## Steps to reproduce


> Status: `repro: technique-authored` — authored and reviewed for correctness against the open-redirect class. Not executed against a live host; live confirmation needs an in-scope target.


### Preconditions
- The target exposes an endpoint that takes a URL/path in a parameter and issues an HTTP redirect to it (e.g. `?next=`, `?redirect=`, `?return=`, `?goto=`, `?url=`).
- The redirect target is derived from attacker-controlled input and is not constrained to a same-origin allowlist.


### Steps
1. Identify a redirecting parameter (see `## Params`). Establish a baseline: request it with an on-site relative value and confirm a 3xx to a same-origin `Location`.
2. Replace the value with an off-origin absolute URL you control.
3. Send the request with redirects disabled and inspect the `Location` response header.


Example request (placeholder host `TARGET`):
```
GET /login?next=https://attacker.example/landing HTTP/1.1 Host: TARGET


```
(also test schema-relative `//attacker.example`, backslash `/\attacker.example`, and `https://TARGET@attacker.example/` allowlist-bypass variants.)


### Success condition (machine-checkable)
- Response status is 301/302/303/307/308 AND the `Location` header resolves to a host outside the target's registrable domain (host == `attacker.example`, not `TARGET`). Confirmed when a client following the redirect lands on the attacker-controlled origin.


### False-positive guard
- NOT a finding if the server normalizes/rejects the value (`Location` stays on-origin, or returns 400), if it only reflects the URL in the HTML body without issuing a redirect to it, or if it redirects to a fixed error/login page regardless of input. A redirect to `TARGET`-owned subdomains on the official allowlist is also not this bug.
