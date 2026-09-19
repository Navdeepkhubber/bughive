# Playbook: Password Reset → ATO
1. HHI or HPP on forgot-password
2. Token leak via response/JS/Referer
3. IDOR on reset id
4. Broken crypto (base64 email, weak MD5)
5. Register username with spaces, reset victim (CVE-2020-7245)
## Severity
Critical
