# SKILL: sqli
## Trigger Conditions
DB-backed inputs: search, filters, sort, ids, login.
## Root Cause Pattern
String concatenation into SQL without parameterization.
## Recon Checklist
- [ ] Search/sort/filter params
- [ ] Hidden params
- [ ] JSON/GraphQL inputs
- [ ] Headers (X-Forwarded-For → stored SQLi)
## Hunt Methodology
1. Boolean `' AND 1=1--` vs `' AND 1=2--`. 2. Time-based.
3. Error-based. 4. Union column match.
## Payload Patterns
`' OR '1'='1` · `1' AND SLEEP(5)--` · `1 UNION SELECT NULL,NULL--`
## WAF Bypass Tips
Inline `/**/` · case mix · whitespace alt · encoding chains
## Triage Guidance
Data extraction Critical · Blind time High · Auth bypass Critical
## Example
Sort param concatenated → boolean SQLi → admin creds dump.
