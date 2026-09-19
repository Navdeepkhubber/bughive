# SKILL: account-takeover
## Triggers
Register, forgot-password, email change, login.
## Root cause
Bad identity checks, email normalization, token leaks, weak crypto.
## Vectors
1. Re-register: victim@x, Victim@x, " victim@x ", victim@x%00
2. Email-verify bypass -> 2fa-bypass.md; normalization flaw on profile update
3. Forgot-password -> password-reset-flow.md
4. Login response manipulation; broken session mgmt; OAuth/JWT/SAML misconfig
5. CSRF on email/password change; stored HTMLi steals CSRF token
6. Reflected XSS -> cookie theft; admin bypass: SQLi, strcmp, type juggling
7. Support-portal abuse: fake mailer, ticket hijack
8. SMTP injection on verify; pre-ATO: change email before verifying
9. Broken cookie crypto; access token leaked via GET -> wayback
10. Company-email quirks: mehul@target.com (space), mehul@TARGET.com
11. Trailing/leading-space username collides w/ victim (CVE-2020-7245)
12. HPP on auth params; IDOR on any token; session outlives reset
## Triage
Full ATO -> Critical. Pre-ATO/token leak -> High.
