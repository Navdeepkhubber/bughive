# SKILL: oauth
## Vectors
1. redirect_uri → attacker.com
2. Referer → attacker.com
3. Pre-ATO: password flow + OAuth same email → login with old creds
4. Token reuse
5. Missing state
6. Missing origin check
7. Open redirect as redirect_uri
8. Change email param after signin
9. Remove email scope, add victim manually
## Payloads
redirect_uri=https://attacker.com/cb
redirect_uri=https://target.com.attacker.com/cb
redirect_uri=https://target.com@attacker.com/cb
redirect_uri=https://target.com/cb?next=https://attacker.com
## Triage
redirect_uri → ATO → Critical. Missing state → High.
