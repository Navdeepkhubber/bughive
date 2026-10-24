# SKILL: ssti
## Trigger Conditions
User text rendered into a server template (name, greeting, error, email body).
## Root Cause Pattern
The template engine evaluates input instead of treating it as data.
## Recon Checklist
- [ ] Query or body fields echoed in HTML
- [ ] Error pages that quote the input
## Hunt Methodology
1. Baseline a plain token. 2. Send an arithmetic expression the engine understands.
3. Confirm the product is present and the raw expression is not.
## Payload Patterns
`{{7*7}}` · `${7*7}` · `<%= 7*7 %>`
## Triage Guidance
Confirmed evaluation is high. A reflected expression with no evaluation is not SSTI.
## Example
`/render?name={{7*7}}` returns 49 and does not return the braces.
