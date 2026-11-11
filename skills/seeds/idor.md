---
repro: technique-authored
---

# SKILL: idor
## Params
id, uid, user, userid, email, username
## Bypass techniques
1. Swap unique id A ↔ B
2. HPP: id=123&id=1234, {"id":[123,1234]}, {"id":123,"id":1234}
3. Change method GET/POST/PUT
4. /api/users/myinfo → /api/admin/myinfo
5. POST /api/data?id=attacker (body id=victim)
6. Append .json: /users/1234.json
7. Older API version /v1/ vs /v2/
8. Wrap id in array: {"id":[1234]}
9. Wrap in object: {"id":{"id":1234}}
10. PATCH body id: {"id":1234, "email":"x"}
11. Case: /ADMIN/profile
12. Path traversal: /users/delete/ATTACKER/../VICTIM
13. Direct: /reports/victim.txt
14. ?action=edit on other user
15. Unsubscribe URL in email
16. UUID guess (v1 timestamp)
17. Base64 decode/mutate
## Triage
PII → High. Auth bypass → Critical.

## Steps to reproduce


> Status: `repro: technique-authored` — authored and reviewed for correctness against the IDOR/BOLA class. Not executed against a live host; live confirmation needs an in-scope target.


### Preconditions
- An object-scoped endpoint keys access on an identifier in the path/query/body (see `## Params`: `id`, `uid`, `user`, `userid`, etc.).
- You control two distinct test identities: attacker account A (its session/token) and victim account B (you know B's object identifier and its expected private data).


### Steps
1. As account B, access one of B's own objects and record its identifier and a piece of data unique to B (e.g. B's email).
2. As account A, replay the exact same request but substitute B's identifier, keeping A's own authenticated session/token.
3. Compare the response: does A receive B's data?


Example request (placeholder host `TARGET`; `A.session`/`A.token` are account A's own credentials, `B_OBJECT_ID` is B's object):
```
GET /api/v1/users/B_OBJECT_ID/profile HTTP/1.1 Host: TARGET Authorization: Bearer A.token


```
(also test the array/object-wrap, HPP, method-swap, and `.json`-suffix variants in `## Bypass techniques`.)


### Success condition (machine-checkable)
- Response status is 200 AND the body contains data belonging to account B (the unique field recorded in step 1, e.g. B's email/PII), while the request carried only account A's credentials. Cross-tenant data return under A's auth confirms IDOR/BOLA.


### False-positive guard
- NOT a finding if the endpoint returns 401/403/404, returns A's own object (server ignored the swapped id and scoped to the session), returns empty/redacted data, or returns only non-sensitive data that is intentionally public. Also confirm the identifier truly belongs to B and not to A — verify against the baseline from step 1.
