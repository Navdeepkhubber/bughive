# SKILL: request-smuggling
## Trigger
Any target behind a reverse proxy/load balancer/CDN (almost all of them).
## Root cause
Frontend and backend disagree on where one request ends and the next begins.
## Vectors
1. CL.TE: frontend uses Content-Length, backend uses Transfer-Encoding
2. TE.CL: frontend uses Transfer-Encoding, backend uses Content-Length
3. TE.TE: both use TE but one ignores it via obfuscation: "xchunked",
   "Transfer-Encoding : chunked", tab before value, duplicate TE headers
4. H2.CL / H2.TE: HTTP/2 downgraded to HTTP/1.1, backend parses differently
5. Blind detection via timing: ambiguous request, measure phantom-body delay
6. Response-queue poisoning: pollute the next real user's response
7. Bypass a frontend auth/WAF check that only inspects the first request
8. Chain into cache poisoning: smuggled response cached for another path
## Probe (CL.TE)
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
## Triage
Confirmed, affects other users -> Critical. Timing-only detection -> High, needs manual confirm.
