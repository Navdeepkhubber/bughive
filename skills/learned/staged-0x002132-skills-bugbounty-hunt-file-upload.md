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

<!-- provenance: {"id":"learned/staged-0x002132-skills-bugbounty-hunt-file-upload","class":"file-upload","classes":["file-upload"],"mode":"derived","source_repo":"0x002132/skills-bugbounty","source_path":"hunt-file-upload/SKILL.md","source_author":"unknown","source_license":"none","source_commit":"unknown","fetched":"2026-10-23T20:17:14.023428+00:00","staged":"0x002132-skills-bugbounty-hunt-file-upload.staged.md"} -->

## Provenance
```json
{
  "id": "learned/staged-0x002132-skills-bugbounty-hunt-file-upload",
  "class": "file-upload",
  "classes": [
    "file-upload"
  ],
  "mode": "derived",
  "source_repo": "0x002132/skills-bugbounty",
  "source_path": "hunt-file-upload/SKILL.md",
  "source_author": "unknown",
  "source_license": "none",
  "source_commit": "unknown",
  "fetched": "2026-10-23T20:17:14.023428+00:00",
  "staged": "0x002132-skills-bugbounty-hunt-file-upload.staged.md"
}
```
