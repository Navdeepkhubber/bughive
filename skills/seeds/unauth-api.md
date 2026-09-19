# SKILL: unauth-api
## Trigger Conditions
APIs reachable without Authorization header / session cookie.
## Root Cause Pattern
Route registered without auth middleware, or middleware bypassable.
## Recon Checklist
- [ ] /docs, /openapi.json, /swagger-ui
- [ ] GraphQL introspection
- [ ] Versioned endpoints (/v1 vs /v2)
- [ ] Internal routes leaked via JS
## Hunt Methodology
1. Enumerate from JS/docs/sitemap. 2. Strip Authorization → observe.
3. Weak auth: Bearer null, Bearer 0, empty JWT. 4. Chain to data extraction.
## Payload Patterns
`Authorization: Bearer null` · `X-Original-URL: /admin` · trailing `//`, `..;/`
## WAF Bypass Tips
Case/encoding/path normalization · method override headers
## Triage Guidance
PII/financial Critical · Config leak High · Public data Low
## Example
`GET /api/v1/users` no auth → 40K PII leak.
