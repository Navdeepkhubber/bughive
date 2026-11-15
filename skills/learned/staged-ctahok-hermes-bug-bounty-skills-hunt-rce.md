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

<!-- provenance: {"id":"learned/staged-ctahok-hermes-bug-bounty-skills-hunt-rce","class":"rce","classes":["rce"],"mode":"derived","source_repo":"ctahok/hermes-bug-bounty-skills","source_path":"hunt-rce/SKILL.md","source_author":"Ilkin Jamalli","source_license":"unspecified","source_commit":"9332d55c70a815441d35d7688791ce1f69b50e49","fetched":"2026-11-08T12:31:10.340502+00:00","staged":"ctahok-hermes-bug-bounty-skills-hunt-rce.staged.md"} -->

## Provenance
```json
{
  "id": "learned/staged-ctahok-hermes-bug-bounty-skills-hunt-rce",
  "class": "rce",
  "classes": [
    "rce"
  ],
  "mode": "derived",
  "source_repo": "ctahok/hermes-bug-bounty-skills",
  "source_path": "hunt-rce/SKILL.md",
  "source_author": "Ilkin Jamalli",
  "source_license": "unspecified",
  "source_commit": "9332d55c70a815441d35d7688791ce1f69b50e49",
  "fetched": "2026-11-08T12:31:10.340502+00:00",
  "staged": "ctahok-hermes-bug-bounty-skills-hunt-rce.staged.md"
}
```
