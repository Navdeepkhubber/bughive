# SKILL: csrf-token-bypass
## Vectors
1. Remove entire param + value; remove only the value (csrf=)
2. Random same-length token; random +/-1-length token
3. A's token in B's session
4. POST -> GET, dropping the token
5. Method override: ?_method=PUT or _method=PUT
6. Custom-header removal; Content-Type swap: json, text/plain, multipart
7. CRLF on double-submit cookie
8. Referrer stripped: <meta name="referrer" content="never">
9. Referrer regex bypass -- attacker.com hosting: ?target.com, ;target.com,
   /target.com/../targetPATH, target.com.attacker.com, attackertarget.com,
   target.com@attacker.com, #target.com, \.target.com, /.target.com
10. Steal via XSS/HTMLi/CORS; JSON CSRF via Content-Type: text/plain
11. Guessable token: base64(username)
12. Clickjacking
13. Type juggling: {"csrftoken":0}; array: csrftoken[]=lol; null: {"csrftoken":null}
14. Token sent over HTTP or to a third party
15. Static+dynamic token part; logout CSRF chained with forum/social action
## Triage
Sensitive action -> High/Critical. Logout only -> Low.
