# SKILL: cors
## Trigger Conditions
API responses readable from a browser, especially with cookies or Authorization.
## Root Cause Pattern
The server copies the request Origin into Access-Control-Allow-Origin and also sends Allow-Credentials.
## Recon Checklist
- [ ] Authenticated JSON endpoints
- [ ] Wildcard ACAO together with credentials
## Hunt Methodology
1. Request with no Origin. 2. Repeat with an origin you control.
3. Confirm the exact origin is reflected and credentials are allowed. A bare `*` is not this bug.
## Payload Patterns
`Origin: https://example.invalid`
## Triage Guidance
Reflected origin plus credentials is medium/high. `*` without credentials is not a finding.
## Example
`ACAO: https://example.invalid` and `ACAC: true` on a credentialed API.
