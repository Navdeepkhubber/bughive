# SKILL: nosql
## Trigger Conditions
JSON or query objects passed into a document query (Mongo-style).
## Root Cause Pattern
Operator keys from the client (`$ne`, `$gt`, `$where`) reach the matcher.
## Recon Checklist
- [ ] Search parameters
- [ ] Login JSON bodies
## Hunt Methodology
1. Baseline a value that matches nothing. 2. Send the same field as an operator.
3. Confirm the result set grows and the response shows the operator was interpreted.
## Payload Patterns
`q[$ne]=x` · `{"email":{"$gt":""}}`
## Triage Guidance
Operator accepted and extra rows returned is high. A quoted operator that is searched as text is not.
## Example
`/api/search?q[$ne]=x` returns every user; `q=nobody` returns none.
