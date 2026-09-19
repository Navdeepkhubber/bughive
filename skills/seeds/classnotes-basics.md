# SKILL: classnotes-basics
## HTTP Methods
- GET: params in URL, cached
- POST: params in body
- PUT: store/modify — dangerous if unauth
- DELETE: destroy — dangerous if unauth
- OPTIONS: introspect allowed methods
## Test
OPTIONS / HTTP/1.1
PUT /1.txt HTTP/1.1
DELETE /1.txt HTTP/1.1
_method=PUT / _method=DELETE
## Triage
Unauth PUT → High/Critical. Unauth DELETE → Critical.
