## Dependencies
Runs after: 06, 12

# Recon Phase: 15-mass-oneliners

## Workspace
Write all output to the absolute path passed in the prompt
(`~/.dsh/hunts/<domain>/recon/15-mass-oneliners/`). Use absolute paths in
your `output_files` array. Do not write anywhere else.

## Input
`all_endpoints` (from phase 06/12) filtered to URLs containing at least
one `=` (i.e. carrying query parameters) for the XSS/SSRF/SSTI checks; the
phase-12 response-cache `.headers` files for the CORS check. If a
`scope.txt` exists, read it first.

## Why this phase exists
These four checks are cheap enough to run across the *entire* endpoint
corpus with plain CLI pipelines, with zero LLM tokens spent, before
hypothesis generation ever starts. Catching reflected XSS/SSTI/open-CORS
this way costs a few seconds of `qsreplace`+`httpx`, not an LLM call per
candidate. Whatever survives this pass is a confirmed hit, not a
hypothesis -- send it to the falsifier stage to rule out false positives,
same as nuclei matches.

## Timeout contract
- Whole phase: 15 minutes wall-clock
- Requires `qsreplace` and `httpx`; if either is missing, skip the checks
  that need it and note why -- do not attempt a manual substitute inline.

## Steps
1. Reflected-marker XSS check.
2. SSRF / open-redirect check (requires an out-of-band collaborator URL --
   see below; skip with a note if none is configured).
3. Server-side template injection (SSTI) check via arithmetic proof.
4. CORS misconfiguration check against cached headers.
5. Write `summary.json`. Return ONLY the JSON summary.

## Output contract
```json
{
  "phase": "15-mass-oneliners",
  "domain": "<root domain>",
  "tools_run": ["qsreplace", "httpx"],
  "tools_skipped": [{ "tool": "...", "reason": "..." }],
  "count": <int, hits across all four checks>,
  "items": [
    { "check": "xss|ssrf|ssti|cors", "url": "...", "evidence": "..." }
  ],
  "notes": [...],
  "output_files": ["<absolute paths to vuln output files>"]
}
```

## Phase procedure

**XSS** — replace every param value with a marker, check if it reflects
unescaped:
```
cat all_endpoints | grep "=" | qsreplace '"><bughive-xss-marker>' | httpx -ms "<bughive-xss-marker>" -o vuln-xss
```

**SSRF / open redirect** — replace every param value with an operator-
controlled out-of-band collaborator URL (interactsh, Burp Collaborator, or
equivalent -- this must be configured by the operator; if none is
available, skip this check and note it rather than using a third-party
URL you don't control):
```
cat all_endpoints | grep "=" | qsreplace "$COLLABORATOR_URL" | httpx -fr -o vuln-ssrf
```
A hit here is a candidate, not a confirmed SSRF -- it proves the app made
an outbound request to your marker, which still needs the falsifier stage
to rule out (e.g.) the app simply reflecting the URL back to the client's
own browser rather than fetching it server-side.

**SSTI** — replace every param value with an arithmetic expression a
template engine would evaluate but a literal string would not, then check
for the computed result in the response:
```
cat all_endpoints | grep "=" | qsreplace '{{4327*8191}}' | httpx -ms "35442497" -o vuln-ssti
```

**CORS** — grep the cached response headers for permissive
credential-sharing configuration:
```
find <phase-12-cache-dir> -name '*.headers' -type f -exec grep -l "Access-Control-Allow-Credentials: true" {} +
```
then check whether `Access-Control-Allow-Origin` on the same response
reflects an arbitrary origin or a wildcard alongside it -- that combination
is the actual misconfiguration, not the credentials header alone.

Every hit from this phase carries a `check` field so downstream stages
(falsifier, skill-select) know which skill file's technique it matches
(`xss.md`, `ssrf.md`, `open-redirect.md`, `csrf-token-bypass.md`/CORS notes).
