# SKILL: rce
## Trigger Conditions
A parameter that reaches a command or template.
## Root Cause Pattern
The process runs caller input.
## Recon Checklist
- [ ] In-scope endpoint that matches this class
## Hunt Methodology
Confirm with a benign marker you control, on an in-scope host, and save the response.
## Payload Patterns
Use the pinned bughive rule for this class. Do not add a payload that the rule does not already send.
## WAF Bypass Tips
Stay inside scope. A bypass is not a finding until the baseline and the probe are both saved.
## Triage Guidance
Unverified output stays unverified. Confirmed means a saved exchange or a verified API result.
## Example
The local fixture returns a different saved response for the probe than for the baseline.

<!-- provenance: {"id":"learned/staged-0x002132-skills-bugbounty-hunt-rce","class":"rce","classes":["rce"],"mode":"derived","source_repo":"0x002132/skills-bugbounty","source_path":"hunt-rce/SKILL.md","source_author":"unknown","source_license":"none","source_commit":"unknown","fetched":"2026-10-23T20:17:14.018200+00:00","staged":"0x002132-skills-bugbounty-hunt-rce.staged.md"} -->

## Provenance
```json
{
  "id": "learned/staged-0x002132-skills-bugbounty-hunt-rce",
  "class": "rce",
  "classes": [
    "rce"
  ],
  "mode": "derived",
  "source_repo": "0x002132/skills-bugbounty",
  "source_path": "hunt-rce/SKILL.md",
  "source_author": "unknown",
  "source_license": "none",
  "source_commit": "unknown",
  "fetched": "2026-10-23T20:17:14.018200+00:00",
  "staged": "0x002132-skills-bugbounty-hunt-rce.staged.md"
}
```
