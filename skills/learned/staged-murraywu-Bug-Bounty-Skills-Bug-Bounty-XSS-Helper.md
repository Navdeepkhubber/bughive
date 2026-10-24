# SKILL: xss
## Trigger Conditions
A parameter reflected into HTML.
## Root Cause Pattern
The reflection is not escaped for the surrounding context.
## Recon Checklist
- [ ] In-scope endpoint that matches this class
## Hunt Methodology
A saved response must contain the unescaped marker. A reflected string alone is not a finding.
## Payload Patterns
Use the pinned bughive rule for this class. Do not add a payload that the rule does not already send.
## WAF Bypass Tips
Stay inside scope. A bypass is not a finding until the baseline and the probe are both saved.
## Triage Guidance
Unverified output stays unverified. Confirmed means a saved exchange or a verified API result.
## Example
The local fixture returns a different saved response for the probe than for the baseline.

<!-- provenance: {"id":"learned/staged-murraywu-Bug-Bounty-Skills-Bug-Bounty-XSS-Helper","class":"xss","classes":["xss"],"mode":"derived","source_repo":"murraywu/Bug-Bounty-Skills","source_path":"Bug-Bounty-XSS-Helper/SKILL.md","source_author":"unknown","source_license":"none","source_commit":"unknown","fetched":"2026-10-23T20:17:15.479556+00:00","staged":"murraywu-Bug-Bounty-Skills-Bug-Bounty-XSS-Helper.staged.md"} -->

## Provenance
```json
{
  "id": "learned/staged-murraywu-Bug-Bounty-Skills-Bug-Bounty-XSS-Helper",
  "class": "xss",
  "classes": [
    "xss"
  ],
  "mode": "derived",
  "source_repo": "murraywu/Bug-Bounty-Skills",
  "source_path": "Bug-Bounty-XSS-Helper/SKILL.md",
  "source_author": "unknown",
  "source_license": "none",
  "source_commit": "unknown",
  "fetched": "2026-10-23T20:17:15.479556+00:00",
  "staged": "murraywu-Bug-Bounty-Skills-Bug-Bounty-XSS-Helper.staged.md"
}
```
