# SKILL: graphql
## Trigger Conditions
A GraphQL endpoint.
## Root Cause Pattern
Introspection or a mutation is exposed without an auth check.
## Recon Checklist
- [ ] In-scope endpoint that matches this class
## Hunt Methodology
Save the request that returned the schema or executed the mutation.
## Payload Patterns
Use the pinned bughive rule for this class. Do not add a payload that the rule does not already send.
## WAF Bypass Tips
Stay inside scope. A bypass is not a finding until the baseline and the probe are both saved.
## Triage Guidance
Unverified output stays unverified. Confirmed means a saved exchange or a verified API result.
## Example
The local fixture returns a different saved response for the probe than for the baseline.

<!-- provenance: {"id":"learned/staged-0x002132-skills-bugbounty-hunt-graphql","class":"graphql","classes":["graphql"],"mode":"derived","source_repo":"0x002132/skills-bugbounty","source_path":"hunt-graphql/SKILL.md","source_author":"unknown","source_license":"none","source_commit":"unknown","fetched":"2026-10-23T20:17:14.021229+00:00","staged":"0x002132-skills-bugbounty-hunt-graphql.staged.md"} -->

## Provenance
```json
{
  "id": "learned/staged-0x002132-skills-bugbounty-hunt-graphql",
  "class": "graphql",
  "classes": [
    "graphql"
  ],
  "mode": "derived",
  "source_repo": "0x002132/skills-bugbounty",
  "source_path": "hunt-graphql/SKILL.md",
  "source_author": "unknown",
  "source_license": "none",
  "source_commit": "unknown",
  "fetched": "2026-10-23T20:17:14.021229+00:00",
  "staged": "0x002132-skills-bugbounty-hunt-graphql.staged.md"
}
```
