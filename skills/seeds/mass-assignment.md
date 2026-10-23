# SKILL: mass-assignment
## Trigger Conditions
Profile or signup JSON copied onto a stored object.
## Root Cause Pattern
The handler assigns the client object without an allowlist, so role or owner is writable.
## Recon Checklist
- [ ] PUT/POST profile, user, and signup bodies
## Hunt Methodology
1. Baseline a harmless field and record the privilege bit.
2. Repeat with a privilege field. 3. Confirm the bit flipped and the baseline had not.
## Payload Patterns
`{"role":"admin"}` · `{"isAdmin":true}`
## Triage Guidance
A privilege field that sticks is high. Ignoring unknown fields is not.
## Example
POST profile `{"nickname":"x"}` stays a user; `{"role":"admin"}` returns isAdmin true.
