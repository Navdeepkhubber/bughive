## Dependencies
Runs after: 04, 05, 06

# Recon Phase: 12-response-cache

## Workspace
Write all output to the absolute path passed in the prompt
(`~/.dsh/hunts/<domain>/recon/12-response-cache/`). Use absolute paths in your
`output_files` array. Do not write anywhere else.

## Input
The merged, de-duplicated endpoint list from phases 04/05/06 (`all_endpoints`
— union of http-probe hosts, content-discovery hits, and param-discovery
URLs, minus static-asset extensions per phase 05's list). If a `scope.txt`
exists, read it first — treat every hostname not listed there as
out-of-scope.

## Why this phase exists
Every phase before this one either checks a single signal (status, header,
title) or re-fetches live on demand. Nothing keeps a local copy of full
response bodies. That local copy is the foundation the proven methodology
this repo is modeled on builds everything else on top of: secret scanning
(phase 13), the oneliner mass-tests (phase 15), and manual "interesting
endpoint" triage all run against this cache instead of re-hitting the live
target for every single check. Concretely this means: fewer requests
against the target (politeness/rate-limit budget), cheaper repeated
analysis (grep a local file instead of an LLM-driven re-fetch), and a
durable artifact a human can grep by hand later.

## Timeout contract
- Per-host fetch: 15s, wrapped in `timeout`
- Whole phase: 20 minutes wall-clock, wrapped at the orchestration level
- Concurrency: cap at 20 in-flight requests (`-c 20` if using a batching
  tool) to stay polite to the target

## Steps
1. Read `all_endpoints` (deduped, static assets already excluded).
2. Fetch every URL, following redirects, and write:
   - `<host>/<sanitized-path>.body` — raw response body
   - `<host>/<sanitized-path>.headers` — response headers, one per line
3. Prefer `fff` (tomnomnom/fff) for this: `cat all_endpoints | fff -S -k -o response-cache/`.
   Fallback: a simple curl loop (`curl -sS -D <path>.headers -o <path>.body <url>`)
   if `fff` isn't installed.
4. Write `summary.json` to the phase directory.
5. Return ONLY the JSON summary. No prose.

## Output contract
```json
{
  "phase": "12-response-cache",
  "domain": "<root domain>",
  "tools_run": ["fff"],
  "tools_skipped": [{ "tool": "...", "reason": "..." }],
  "count": <int, endpoints cached>,
  "items": [],
  "notes": ["cache root: <absolute path>"],
  "output_files": ["<absolute path to the cache directory>"]
}
```

## Phase procedure
Fetch every URL in `all_endpoints` and write its response body + headers
locally under this phase's directory, one file pair per endpoint, using a
filesystem-safe name derived from the URL (scheme/host stripped of `:` and
`/`, e.g. `https://example.com/api/v1/users` ->
`example.com_api_v1_users`). This cache is the input to phases 13 and 15.
