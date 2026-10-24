# SKILL: saml
## Trigger Conditions
A SAML response the server accepts.
## Root Cause Pattern
The signature or audience is not checked.
## Recon Checklist
- [ ] In-scope endpoint that matches this class
## Hunt Methodology
Save the response that was accepted.
## Payload Patterns
Use the pinned bughive rule for this class. Do not add a payload that the rule does not already send.
## WAF Bypass Tips
Stay inside scope. A bypass is not a finding until the baseline and the probe are both saved.
## Triage Guidance
Unverified output stays unverified. Confirmed means a saved exchange or a verified API result.
## Example
The local fixture returns a different saved response for the probe than for the baseline.

## Provenance
Original house-style seed for `saml`. Per-source attribution is on the matching `skills/learned/staged-*` files.
