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

<!-- provenance: {"id":"learned/staged-0x002132-skills-bugbounty-hunt-idor","class":"idor","classes":["idor","idor-write"],"mode":"derived","source_repo":"0x002132/skills-bugbounty","source_path":"hunt-idor/SKILL.md","source_author":"0x002132","source_license":"unspecified","source_commit":"566781c54b60b3cc687c2fbf7a1f8e73c3ebdf52","fetched":"2026-11-15T13:14:41.230240+00:00","staged":"0x002132-skills-bugbounty-hunt-idor.staged.md"} -->

## Provenance
```json
{
  "id": "learned/staged-0x002132-skills-bugbounty-hunt-idor",
  "class": "idor",
  "classes": [
    "idor",
    "idor-write"
  ],
  "mode": "derived",
  "source_repo": "0x002132/skills-bugbounty",
  "source_path": "hunt-idor/SKILL.md",
  "source_author": "0x002132",
  "source_license": "unspecified",
  "source_commit": "566781c54b60b3cc687c2fbf7a1f8e73c3ebdf52",
  "fetched": "2026-11-15T13:14:41.230240+00:00",
  "staged": "0x002132-skills-bugbounty-hunt-idor.staged.md"
}
```
