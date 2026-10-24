# SKILL: secret-detection
## Trigger Conditions
Source, responses, or repos that may contain access keys.
## Root Cause Pattern
A credential was committed or returned. A regex hit is only a candidate until a verifier says the key works.
## Recon Checklist
- [ ] Repos, env files, JS bundles
- [ ] Vendor example keys and documentation placeholders
## Hunt Methodology
1. Match the vendor pattern. 2. Drop allowlisted example keys and stopwords.
3. Leave the rest unverified unless a live check (unmodified TruffleHog, when installed) returns verified.
## Payload Patterns
AWS access key id shape `AKIA` plus 16 uppercase alphanumerics. Never treat `EXAMPLE` keys as confirmed.
## Triage Guidance
Verified key is high. Unverified is a lead, not a confirmed finding. Allowlisted examples are noise.
## Example
`AKIAIOSFODNN7EXAMPLE` is the AWS documentation key and is not reported.
