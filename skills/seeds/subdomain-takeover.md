---
# bughive-repro-start
cve: null
repro: unverified
# bughive-repro-end
---

# SKILL: subdomain-takeover
## Fingerprints
S3: NoSuchBucket
GitHub Pages: "There isn't a GitHub Pages site here"
Heroku: "No such app"
Netlify, Vercel, Azure, Fastly, Shopify: provider-specific
## Hunt
1. Enumerate subdomains, resolve CNAMEs
2. Request each resource
3. Match fingerprints
4. Claim, prove control, report (do NOT abuse)
5. Tools: HostileSubBruteforcer, Can-I-Takeover-XYZ
## Triage
Claimable + cookie-scoped → Critical. Unclaimable → Informational.

<!-- bughive-repro-start -->
## Steps to reproduce

> Status: `repro: unverified` — no CVE was resolved for this skill. Nothing below was invented.

### What's missing
- no CVE/target in skill; needs teardown or stays unverified
<!-- bughive-repro-end -->
