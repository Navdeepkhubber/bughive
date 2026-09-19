## Dependencies
Runs after: 06, 12

# Recon Phase: 17-interesting-endpoints

## Workspace
Write all output to the absolute path passed in the prompt
(`~/.dsh/hunts/<domain>/recon/17-interesting-endpoints/`). Use absolute
paths in your `output_files` array. Do not write anywhere else.

## Input
`all_endpoints` (from phases 04/05/06) and, where present, the phase-12
response cache. If a `scope.txt` exists, read it first.

## Why this phase exists
This is pure triage, not testing: flag the URLs worth a human or the
hypothesis stage looking at first, before spending any reasoning budget on
the full endpoint list. It's a single grep pass -- cheap enough that
skipping it only means the hypothesis stage has to rediscover the same
priority signal the hard way, later, at LLM-token cost instead of grep
cost.

## Timeout contract
Whole phase: 2 minutes. This is a grep pass, not a network operation --
if it's taking longer than that, something upstream (all_endpoints size)
is the actual problem, not this phase.

## Steps
1. Grep `all_endpoints` for the keyword list below.
2. Grep the phase-12 cache bodies (if present) for the same list, in case
   a keyword only appears inside a response rather than the URL itself
   (e.g. a link to `/admin` embedded in a JS file, not yet in the URL list).
3. Write `summary.json`. Return ONLY the JSON summary.

## Output contract
```json
{
  "phase": "17-interesting-endpoints",
  "domain": "<root domain>",
  "tools_run": ["grep"],
  "tools_skipped": [],
  "count": <int, matches>,
  "items": [{ "url": "...", "matched_keyword": "..." }],
  "notes": [...],
  "output_files": ["<absolute paths>"]
}
```

## Phase procedure
```
grep -iE "/(admin|api/|graphql|debug|swagger|internal|openapi|actuator)" all_endpoints
```
Each hit gets one `items[]` entry with the specific keyword that matched
-- this becomes a direct, named recon item the hypothesis stage can cite
(e.g. "endpoint /internal/api/v2/users matched keyword 'internal' + 'api/'
-- test for unauth-api.md technique #2"), rather than the hypothesis
subagent having to rediscover priority endpoints from a flat list on its
own.
