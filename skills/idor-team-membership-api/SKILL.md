---
name: idor-team-membership-api
description: Hunt and validate IDOR where team, group, or workspace membership data is returned at the API level by ID without an ownership or membership check. Use when the target has teams, organizations, workspaces, projects, or groups and an API returns members, roles, or invites keyed by an identifier, or the user mentions IDOR, object-level authorization, broken access control, or team member enumeration.
---

# IDOR: Team Membership Returned by API ID

## 1 Trigger Conditions
- Feature has a container entity: team, org, workspace, tenant, project, group.
- Endpoint returns membership: `/members`, `/users`, `/participants`, `/collaborators`, `/roles`, `/invites`.
- Identifier is guessable: sequential int, short UUID, slug, or base64 of an int.
- You can reach the object as a non-member (or are removed/never invited).
- Higher value if response includes emails, roles, or names of private teams.

## 2 Root Cause Pattern
The handler authorizes the *caller* (valid session) but not the *object*. It loads membership with `WHERE teamId = :id` and never asserts the caller is in that team. Row-level ownership check is missing on the read path; often present on the write path, which proves intent.

## 3 Recon Checklist
- [ ] Capture every response containing `team_id`, `org_id`, `workspaceId`, `gid`, `tid`, `uuid`.
- [ ] Enumerate member-bearing routes from JS bundles, OpenAPI/Swagger, mobile API, and GraphQL schema.
- [ ] Note your own team ID and its neighbors before testing.
- [ ] Map plural/singular and versioned variants: `/api/v1/teams/{id}`, `/teams/{id}/members`, `/ocs/v2.php/...`.
- [ ] Check `?format=json|xml`, trailing slash, and `/api/v2` variants.
- [ ] Record role: can an outsider with no membership still read?

## 4 Hunt Methodology
1. Baseline: request your own team ID, save the full response body verbatim.
2. Probe: same request, swap ID by ±1, then ±2, then a far offset.
3. Diff: size, member count, 200 vs 403/404, timing.
4. Confirm no membership: use a second account with zero relation, or an account removed from the team.
5. Enumerate: iterate a bounded range only to prove impact; stop at proof.
6. Escalate: does `role` include owners? Are emails returned? Can the same ID be used on `/members/export` or invites?
7. Chain candidates: leaked emails → invite abuse, password reset, or SSO enumeration; leaked user IDs → user-object IDOR.

## 5 Payload Patterns
- `GET /api/v1/teams/1002/members` vs `/1001/members`
- `{"team_id": 1002}` in POST body where GET is filtered but POST is not.
- Alternate encodings of the same ID: `1002 `, `01002`, `1002.0`, `MTAwMg==`, UUID variant case.
- Method swap: `GET`→`HEAD`/`OPTIONS` (metadata), `PUT`/`POST` with empty body returns members.
- Nested path: `/teams/1002/members/` and `/members?team_id=1002`.
- GraphQL: `query { team(id: 1002) { members { email role } } }`.
- Never delete or modify: read-only probes only. No bulk scraping.

## 6 WAF Bypass Tips
- IDOR rarely triggers WAF; focus on app-layer checks instead.
- Rotate the questionable vector: body param over path, JSON over form, GraphQL over REST, mobile User-Agent.
- Try `?format=json` when XML/JSON default differs in auth logic.
- If rate-limited, slow to 1 req/s and use a small ID range; 429 is not a finding.
- Case and trailing-slash variants often skip route-specific middleware (`/Members`, `/teams/1002/members/`).
- Retest after logout/session expiry to confirm the check is truly absent, not cached.

## 7 Triage Guidance
- Valid only with a reproducible baseline/probe diff and proof the caller is not a member.
- Low when only team name/member count leaks; Medium when emails, roles, or invite tokens leak; High when it enables account takeover.
- Kill if: your ID is returned because you are a member, response is generic/empty, 403 on real probe, or public team by design.
- Check Nextcloud-style `/ocs/` responses: parse `ocs.meta.statuscode`, not HTTP status.
- Report impact first: "any authenticated user can enumerate members and emails of any private team."

## 8 Example
Nextcloud, HackerOne #3484601 (Low, IDOR). Team membership information was returned at the API level based on the team ID. Authenticated user sent a team-scoped API request with a foreign team ID and received that team's membership data because the endpoint never verified the caller belonged to the team. Fix: enforce membership on every object read, not just on writes.
