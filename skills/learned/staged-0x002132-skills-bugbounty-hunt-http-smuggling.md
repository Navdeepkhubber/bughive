# SKILL: request-smuggling
## Trigger Conditions
A front-end and back-end that disagree on request length.
## Root Cause Pattern
The boundary is parsed twice.
## Recon Checklist
- [ ] In-scope endpoint that matches this class
## Hunt Methodology
Confirm only with a saved desync, inside scope.
## Payload Patterns
Use the pinned bughive rule for this class. Do not add a payload that the rule does not already send.
## WAF Bypass Tips
Stay inside scope. A bypass is not a finding until the baseline and the probe are both saved.
## Triage Guidance
Unverified output stays unverified. Confirmed means a saved exchange or a verified API result.
## Example
The local fixture returns a different saved response for the probe than for the baseline.

<!-- provenance: {"id":"learned/staged-0x002132-skills-bugbounty-hunt-http-smuggling","class":"request-smuggling","classes":["request-smuggling"],"mode":"derived","source_repo":"0x002132/skills-bugbounty","source_path":"hunt-http-smuggling/SKILL.md","source_author":"unknown","source_license":"none","source_commit":"unknown","fetched":"2026-10-23T20:17:14.018088+00:00","staged":"0x002132-skills-bugbounty-hunt-http-smuggling.staged.md"} -->

## Provenance
```json
{
  "id": "learned/staged-0x002132-skills-bugbounty-hunt-http-smuggling",
  "class": "request-smuggling",
  "classes": [
    "request-smuggling"
  ],
  "mode": "derived",
  "source_repo": "0x002132/skills-bugbounty",
  "source_path": "hunt-http-smuggling/SKILL.md",
  "source_author": "unknown",
  "source_license": "none",
  "source_commit": "unknown",
  "fetched": "2026-10-23T20:17:14.018088+00:00",
  "staged": "0x002132-skills-bugbounty-hunt-http-smuggling.staged.md"
}
```
