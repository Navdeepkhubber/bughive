# SKILL: subdomain-takeover
## Trigger Conditions
A dangling DNS name.
## Root Cause Pattern
The target service is unclaimed.
## Recon Checklist
- [ ] In-scope endpoint that matches this class
## Hunt Methodology
Confirm only when you control the dangling name and the response was saved.
## Payload Patterns
Use the pinned bughive rule for this class. Do not add a payload that the rule does not already send.
## WAF Bypass Tips
Stay inside scope. A bypass is not a finding until the baseline and the probe are both saved.
## Triage Guidance
Unverified output stays unverified. Confirmed means a saved exchange or a verified API result.
## Example
The local fixture returns a different saved response for the probe than for the baseline.

<!-- provenance: {"id":"learned/staged-0x002132-skills-bugbounty-hunt-subdomain","class":"subdomain-takeover","classes":["subdomain-takeover"],"mode":"derived","source_repo":"0x002132/skills-bugbounty","source_path":"hunt-subdomain/SKILL.md","source_author":"0x002132","source_license":"unspecified","source_commit":"566781c54b60b3cc687c2fbf7a1f8e73c3ebdf52","fetched":"2026-11-15T13:14:41.230240+00:00","staged":"0x002132-skills-bugbounty-hunt-subdomain.staged.md"} -->

## Provenance
```json
{
  "id": "learned/staged-0x002132-skills-bugbounty-hunt-subdomain",
  "class": "subdomain-takeover",
  "classes": [
    "subdomain-takeover"
  ],
  "mode": "derived",
  "source_repo": "0x002132/skills-bugbounty",
  "source_path": "hunt-subdomain/SKILL.md",
  "source_author": "0x002132",
  "source_license": "unspecified",
  "source_commit": "566781c54b60b3cc687c2fbf7a1f8e73c3ebdf52",
  "fetched": "2026-11-15T13:14:41.230240+00:00",
  "staged": "0x002132-skills-bugbounty-hunt-subdomain.staged.md"
}
```
