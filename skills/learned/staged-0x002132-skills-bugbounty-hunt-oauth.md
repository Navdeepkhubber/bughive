# SKILL: oauth
## Trigger Conditions
An OAuth redirect or token endpoint.
## Root Cause Pattern
The redirect or state check is missing.
## Recon Checklist
- [ ] In-scope endpoint that matches this class
## Hunt Methodology
Save the response that shows the check was skipped.
## Payload Patterns
Use the pinned bughive rule for this class. Do not add a payload that the rule does not already send.
## WAF Bypass Tips
Stay inside scope. A bypass is not a finding until the baseline and the probe are both saved.
## Triage Guidance
Unverified output stays unverified. Confirmed means a saved exchange or a verified API result.
## Example
The local fixture returns a different saved response for the probe than for the baseline.

<!-- provenance: {"id":"learned/staged-0x002132-skills-bugbounty-hunt-oauth","class":"oauth","classes":["oauth"],"mode":"derived","source_repo":"0x002132/skills-bugbounty","source_path":"hunt-oauth/SKILL.md","source_author":"unknown","source_license":"none","source_commit":"unknown","fetched":"2026-10-23T20:17:14.021736+00:00","staged":"0x002132-skills-bugbounty-hunt-oauth.staged.md"} -->

## Provenance
```json
{
  "id": "learned/staged-0x002132-skills-bugbounty-hunt-oauth",
  "class": "oauth",
  "classes": [
    "oauth"
  ],
  "mode": "derived",
  "source_repo": "0x002132/skills-bugbounty",
  "source_path": "hunt-oauth/SKILL.md",
  "source_author": "unknown",
  "source_license": "none",
  "source_commit": "unknown",
  "fetched": "2026-10-23T20:17:14.021736+00:00",
  "staged": "0x002132-skills-bugbounty-hunt-oauth.staged.md"
}
```
