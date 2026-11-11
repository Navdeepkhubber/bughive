---
# bughive-repro-start
cve: null
repro: unverified
# bughive-repro-end
---

# SKILL: tls
## Trigger Conditions
HTTPS host in scope.
## Root Cause Pattern
The certificate is expired, or a CRL/OCSP check says it was revoked.
## Recon Checklist
- [ ] Live TLS handshake
- [ ] NotAfter, OCSP, CRL
## Hunt Methodology
1. Handshake and record the peer certificate.
2. Expired: the TLS stack rejects it with CERT_HAS_EXPIRED.
3. Revoked: only when OCSP or `openssl verify -crl_check` says revoked. A valid leaf is not a finding.
## Payload Patterns
None. Passive handshake plus the verifier's own output.
## Triage Guidance
Confirmed only from the verifier text or the TLS alert. Do not infer revocation from the hostname.
## Example
expired.badssl.com fails verification with certificate has expired.

<!-- bughive-repro-start -->
## Steps to reproduce

> Status: `repro: unverified` — no CVE was resolved for this skill. Nothing below was invented.

### What's missing
- no CVE/target in skill; needs teardown or stays unverified
<!-- bughive-repro-end -->
