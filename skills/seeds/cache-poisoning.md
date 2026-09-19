# SKILL: cache-poisoning
## Trigger
Any response passing through a shared cache (CDN, reverse proxy) where
the cache key is narrower than what the response actually varies on.
## Root cause
An "unkeyed" input (header/cookie/param the cache ignores) still
changes the response, so poisoning it once poisons the cached copy for
every later visitor of that cache key.
## Vectors
1. Unkeyed header reflected: X-Forwarded-Host/Scheme, X-Original-URL
   reflected into a canonical link or redirect
2. Unkeyed cookie changes content (e.g. an a/b test cookie)
3. "Fat GET": unkeyed extra query param changes content
4. Key normalization mismatch: /path vs /path/ (or extra params) treated
   as same key by cache, not by origin
5. Web cache deception: request a static-looking path
   (/account/settings/x.css) the cache stores, origin returns real
   authenticated page content
6. Vary-header abuse: origin varies on a header the cache ignores
## Confirming
7. Add a cache-buster param, send the payload, then re-request WITHOUT
   payload/buster -- poisoned content coming back proves real poisoning
## Triage
Poisoned response served to others (XSS/redirect/leak) -> Critical/High.
Key confusion, no attacker content -> Medium.
