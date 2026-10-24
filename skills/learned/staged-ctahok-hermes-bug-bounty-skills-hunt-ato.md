# SKILL: account-takeover
## Trigger Conditions
An account recovery or session route.
## Root Cause Pattern
A token or code is bound to the wrong account.
## Recon Checklist
- [ ] In-scope endpoint that matches this class
## Hunt Methodology
Save the response that shows the other account.
## Payload Patterns
Use the pinned bughive rule for this class. Do not add a payload that the rule does not already send.
## WAF Bypass Tips
Stay inside scope. A bypass is not a finding until the baseline and the probe are both saved.
## Triage Guidance
Unverified output stays unverified. Confirmed means a saved exchange or a verified API result.
## Example
The local fixture returns a different saved response for the probe than for the baseline.

<!-- provenance: {"id":"learned/staged-ctahok-hermes-bug-bounty-skills-hunt-ato","class":"account-takeover","classes":["account-takeover"],"mode":"derived","source_repo":"ctahok/hermes-bug-bounty-skills","source_path":"hunt-ato/SKILL.md","source_author":"unknown","source_license":"none","source_commit":"unknown","fetched":"2026-10-23T20:17:12.991069+00:00","staged":"ctahok-hermes-bug-bounty-skills-hunt-ato.staged.md"} -->

## Provenance
```json
{
  "id": "learned/staged-ctahok-hermes-bug-bounty-skills-hunt-ato",
  "class": "account-takeover",
  "classes": [
    "account-takeover"
  ],
  "mode": "derived",
  "source_repo": "ctahok/hermes-bug-bounty-skills",
  "source_path": "hunt-ato/SKILL.md",
  "source_author": "unknown",
  "source_license": "none",
  "source_commit": "unknown",
  "fetched": "2026-10-23T20:17:12.991069+00:00",
  "staged": "ctahok-hermes-bug-bounty-skills-hunt-ato.staged.md"
}
```
