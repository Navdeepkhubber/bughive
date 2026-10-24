# SKILL: file-upload
## Trigger Conditions
An upload that is stored and served.
## Root Cause Pattern
The type or path is not constrained.
## Recon Checklist
- [ ] In-scope endpoint that matches this class
## Hunt Methodology
Confirm with a benign marker file, inside scope.
## Payload Patterns
Use the pinned bughive rule for this class. Do not add a payload that the rule does not already send.
## WAF Bypass Tips
Stay inside scope. A bypass is not a finding until the baseline and the probe are both saved.
## Triage Guidance
Unverified output stays unverified. Confirmed means a saved exchange or a verified API result.
## Example
The local fixture returns a different saved response for the probe than for the baseline.

## Provenance
Original house-style seed for `file-upload`. Per-source attribution is on the matching `skills/learned/staged-*` files.
