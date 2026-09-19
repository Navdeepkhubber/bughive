# SKILL: ratelimit
## Header bypass
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
X-Forwared-Host: 127.0.0.1
## Other
- Change User-Agent, cookies
- Null bytes after endpoint/email: %00, %0d%0a, %0d, %0a, %09, %0C, %20
- Valid → invalid → valid login pattern
- Race: high-thread Intruder
- Random GET/POST param
- Method swap
- Content-Type swap: multipart ↔ JSON ↔ x-www-form-urlencoded
## Triage
2FA brute → High/Critical. Forgot-password spam → Med. DoS → Med/High.
