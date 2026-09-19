# SKILL: csrf-token-bypass
## 22 vectors
1. Remove entire param + value
2. Remove only value: csrf=
3. Random same-length
4. Random ±1-length
5. A's token in B's session
6. POST → GET, drop token
7. Method override: ?_method=PUT or _method=PUT
8. Custom header: remove header
9. Content-Type swap: json, text/plain, multipart
10. CRLF on double-submit
11. Referrer: <meta name="referrer" content="never">
12. Referrer regex bypass:
    https://attacker.com?target.com
    https://attacker.com;target.com
    https://attacker.com/target.com/../targetPATH
    https://target.com.attacker.com
    https://attackertarget.com
    https://target.com@attacker.com
    https://attacker.com#target.com
    https://attacker.com\.target.com
    https://attacker.com/.target.com
13. Steal via XSS/HTMLi/CORS
14. JSON CSRF: Content-Type: text/plain
15. Guessable: base64(username)
16. Clickjacking
17. Type juggling: {"csrftoken":0}
18. Array: csrftoken[]=lol
19. Null: {"csrftoken":null}
20. Token over HTTP / 3rd party
21. Static + dynamic part
22. Logout CSRF + forum
## Triage
Sensitive action → High/Critical. Logout → Low.
