# SKILL: 2fa-bypass
## Triggers
Login has a 2FA step (OTP, TOTP, SMS, email).
## Root cause
Client trust, missing rate limit, non-expiring tokens, response manipulation.
## Vectors
1. Response manip: {"success":false} -> {"success":true}
2. Brute force: 4-digit space = 10K (~1-2 hrs unratelimited)
3. Token reuse after use; code doesn't expire for hours
4. Cross-account: request code on attacker, use on victim
5. Forced browsing: skip /2fa -> /dashboard, spoof Referer
6. Code leaked in response body/JS (search with Burp)
7. CSRF/clickjacking disables 2FA; none needed to disable it
8. Backup-code abuse: POST /backup-code {"action":"BACKUP_CODE_DOWNLOAD"}
9. Enabling 2FA doesn't invalidate existing sessions
10. OAuth path bypasses 2FA; password reset skips it too
11. All-zeros code accepted: 0000 / 000000
12. Request manip: otprequired=false, {"code":null}, {"code":[4567,6789]}
13. 2FA page discloses account info pre-auth; other endpoints reachable after only the 1st factor
14. DoS: register as attacker, enable 2FA, change email to victim's
## Triage
Full bypass -> Critical. Brute force / response manipulation -> High.
