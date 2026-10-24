# SKILL: idor
## Trigger Conditions
An object id the caller did not create.
## Root Cause Pattern
The handler loads the object and skips an authorization check.
## Recon Checklist
- [ ] In-scope endpoint that matches this class
## Hunt Methodology
Read two ids. Confirm only when both responses are saved and belong to different owners.
## Payload Patterns
Use the pinned bughive rule for this class. Do not add a payload that the rule does not already send.
## WAF Bypass Tips
Stay inside scope. A bypass is not a finding until the baseline and the probe are both saved.
## Triage Guidance
Unverified output stays unverified. Confirmed means a saved exchange or a verified API result.
## Example
The local fixture returns a different saved response for the probe than for the baseline.

<!-- provenance: {"id":"learned/staged-ctahok-hermes-bug-bounty-skills-hunt-idor","class":"idor","classes":["idor","idor-write"],"mode":"derived","source_repo":"ctahok/hermes-bug-bounty-skills","source_path":"hunt-idor/SKILL.md","source_author":"unknown","source_license":"none","source_commit":"unknown","fetched":"2026-10-23T20:17:12.991376+00:00","staged":"ctahok-hermes-bug-bounty-skills-hunt-idor.staged.md"} -->

## Provenance
```json
{
  "id": "learned/staged-ctahok-hermes-bug-bounty-skills-hunt-idor",
  "class": "idor",
  "classes": [
    "idor",
    "idor-write"
  ],
  "mode": "derived",
  "source_repo": "ctahok/hermes-bug-bounty-skills",
  "source_path": "hunt-idor/SKILL.md",
  "source_author": "unknown",
  "source_license": "none",
  "source_commit": "unknown",
  "fetched": "2026-10-23T20:17:12.991376+00:00",
  "staged": "ctahok-hermes-bug-bounty-skills-hunt-idor.staged.md"
}
```
