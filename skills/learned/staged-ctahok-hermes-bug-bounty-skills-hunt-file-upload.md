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

<!-- provenance: {"id":"learned/staged-ctahok-hermes-bug-bounty-skills-hunt-file-upload","class":"file-upload","classes":["file-upload"],"mode":"derived","source_repo":"ctahok/hermes-bug-bounty-skills","source_path":"hunt-file-upload/SKILL.md","source_author":"Ilkin Jamalli","source_license":"unspecified","source_commit":"9332d55c70a815441d35d7688791ce1f69b50e49","fetched":"2026-11-15T13:14:41.230240+00:00","staged":"ctahok-hermes-bug-bounty-skills-hunt-file-upload.staged.md"} -->

## Provenance
```json
{
  "id": "learned/staged-ctahok-hermes-bug-bounty-skills-hunt-file-upload",
  "class": "file-upload",
  "classes": [
    "file-upload"
  ],
  "mode": "derived",
  "source_repo": "ctahok/hermes-bug-bounty-skills",
  "source_path": "hunt-file-upload/SKILL.md",
  "source_author": "Ilkin Jamalli",
  "source_license": "unspecified",
  "source_commit": "9332d55c70a815441d35d7688791ce1f69b50e49",
  "fetched": "2026-11-15T13:14:41.230240+00:00",
  "staged": "ctahok-hermes-bug-bounty-skills-hunt-file-upload.staged.md"
}
```
