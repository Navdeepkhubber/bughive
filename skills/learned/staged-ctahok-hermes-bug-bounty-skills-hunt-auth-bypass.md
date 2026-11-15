# SKILL: missing-auth
## Trigger Conditions
An admin or account route.
## Root Cause Pattern
The handler does not require a session.
## Recon Checklist
- [ ] In-scope endpoint that matches this class
## Hunt Methodology
Confirm only when the saved response contains the protected data.
## Payload Patterns
Use the pinned bughive rule for this class. Do not add a payload that the rule does not already send.
## WAF Bypass Tips
Stay inside scope. A bypass is not a finding until the baseline and the probe are both saved.
## Triage Guidance
Unverified output stays unverified. Confirmed means a saved exchange or a verified API result.
## Example
The local fixture returns a different saved response for the probe than for the baseline.

<!-- provenance: {"id":"learned/staged-ctahok-hermes-bug-bounty-skills-hunt-auth-bypass","class":"missing-auth","classes":["missing-auth"],"mode":"derived","source_repo":"ctahok/hermes-bug-bounty-skills","source_path":"hunt-auth-bypass/SKILL.md","source_author":"Ilkin Jamalli","source_license":"unspecified","source_commit":"9332d55c70a815441d35d7688791ce1f69b50e49","fetched":"2026-10-23T20:17:12.991496+00:00","staged":"ctahok-hermes-bug-bounty-skills-hunt-auth-bypass.staged.md"} -->

## Provenance
```json
{
  "id": "learned/staged-ctahok-hermes-bug-bounty-skills-hunt-auth-bypass",
  "class": "missing-auth",
  "classes": [
    "missing-auth"
  ],
  "mode": "derived",
  "source_repo": "ctahok/hermes-bug-bounty-skills",
  "source_path": "hunt-auth-bypass/SKILL.md",
  "source_author": "Ilkin Jamalli",
  "source_license": "unspecified",
  "source_commit": "9332d55c70a815441d35d7688791ce1f69b50e49",
  "fetched": "2026-10-23T20:17:12.991496+00:00",
  "staged": "ctahok-hermes-bug-bounty-skills-hunt-auth-bypass.staged.md"
}
```
