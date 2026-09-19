# Playbook: 2FA Bypass → ATO
1. Response manipulation: {"success":false} → {"success":true}
2. If rate limit weak → brute force 4-digit OTP
3. If token reuse → replay across accounts
4. If forced browsing → skip /2fa
5. Chain to session hijack via cookie theft if XSS
## Severity
Critical
