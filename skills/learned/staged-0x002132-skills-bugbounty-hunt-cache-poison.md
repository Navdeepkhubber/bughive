# SKILL: cache-poisoning
## Trigger Conditions
A response that is cached.
## Root Cause Pattern
A request header changes the body and is left out of the cache key.
## Recon Checklist
- [ ] In-scope endpoint that matches this class
## Hunt Methodology
Save the poisoned response and the baseline.
## Payload Patterns
Use the pinned bughive rule for this class. Do not add a payload that the rule does not already send.
## WAF Bypass Tips
Stay inside scope. A bypass is not a finding until the baseline and the probe are both saved.
## Triage Guidance
Unverified output stays unverified. Confirmed means a saved exchange or a verified API result.
## Example
The local fixture returns a different saved response for the probe than for the baseline.

<!-- provenance: {"id":"learned/staged-0x002132-skills-bugbounty-hunt-cache-poison","class":"cache-poisoning","classes":["cache-poisoning"],"mode":"derived","source_repo":"0x002132/skills-bugbounty","source_path":"hunt-cache-poison/SKILL.md","source_author":"unknown","source_license":"none","source_commit":"unknown","fetched":"2026-10-23T20:17:14.020118+00:00","staged":"0x002132-skills-bugbounty-hunt-cache-poison.staged.md"} -->

## Provenance
```json
{
  "id": "learned/staged-0x002132-skills-bugbounty-hunt-cache-poison",
  "class": "cache-poisoning",
  "classes": [
    "cache-poisoning"
  ],
  "mode": "derived",
  "source_repo": "0x002132/skills-bugbounty",
  "source_path": "hunt-cache-poison/SKILL.md",
  "source_author": "unknown",
  "source_license": "none",
  "source_commit": "unknown",
  "fetched": "2026-10-23T20:17:14.020118+00:00",
  "staged": "0x002132-skills-bugbounty-hunt-cache-poison.staged.md"
}
```
