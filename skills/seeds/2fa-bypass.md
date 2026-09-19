# SKILL: 2fa-bypass
## Trigger Conditions
Login has 2FA step (OTP, TOTP, SMS, email).
## Root Cause
Client-side trust, missing rate limit, non-expiring tokens, response manipulation.
## 19 vectors
1. Response manipulation: {"success":false} → {"success":true}
2. Brute force: 4-digit = 10K (~1-2 hrs)
3. Token reuse after use
4. Cross-account: request on A, use on V
5. Forced browsing: skip /2fa → /dashboard, add Referer: https://target.com/2fa
6. Code leak in response/JS (burp search)
7. CSRF/Clickjacking to disable 2FA
8. Backup code abuse
9. Enabling 2FA doesn't expire sessions
10. OAuth bypasses 2FA
11. No 2FA for disabling 2FA
12. Password reset without 2FA
13. All zeros: 0000 / 000000
14. Request manipulation: otprequired=false, {"code":null}, {"code":[4567,6789]}, remove param, code as array
15. Code doesn't expire after hours
16. Backup code: POST /backup-code {"action":"BACKUP_CODE_DOWNLOAD"}
17. 2FA page discloses info
18. Access other auth endpoints after 1st factor
19. DoS: register attacker, enable 2FA, change email to victim
## Triage
Full bypass → Critical. Brute force → High. Response manipulation → High.
