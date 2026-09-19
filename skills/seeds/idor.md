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
