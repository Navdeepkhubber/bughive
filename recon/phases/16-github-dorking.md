## Dependencies
Runs after: 01

# Recon Phase: 16-github-dorking

## Workspace
Write all output to the absolute path passed in the prompt
(`~/.dsh/hunts/<domain>/recon/16-github-dorking/`). Use absolute paths in
your `output_files` array. Do not write anywhere else.

## Input
The root domain and company/product name (if provided at init). If a
`scope.txt` exists, read it first.

## Why this phase exists
`skills/seeds/github-recon.md` has been a reference checklist with nothing
in recon ever actually running it -- it only ever got used if the
hypothesis stage happened to pick it, by which point there was no GitHub
recon evidence to reason over anyway. This phase closes that gap the same
way phase 14 (nuclei) closes the "vulnerability scanning" gap: run the
automated tool proactively instead of leaving it as a checklist someone
has to remember to consult by hand.

## Timeout contract
- Whole phase: 15 minutes wall-clock (GitHub's search API is rate-limited;
  budget for backoff)
- Requires a GitHub token with search scope (`GITHUB_TOKEN` env var) for
  useful rate limits; runs at a much lower, slower rate unauthenticated.
  Skip and note if no token is configured rather than hammering the
  unauthenticated rate limit.

## Steps
1. Run GitDorker against the target's known company/domain name and any
   discovered internal hostnames (from phase 07/09).
2. De-duplicate hits by repo + file path.
3. Redact any live-looking secret found (this phase reports *where* a
   leak is, not the leaked value itself -- phase 13's redaction rule
   applies here too).
4. Write `summary.json`. Return ONLY the JSON summary.

## Output contract
```json
{
  "phase": "16-github-dorking",
  "domain": "<root domain>",
  "tools_run": ["gitdorker"],
  "tools_skipped": [{ "tool": "gitdorker", "reason": "..." }],
  "count": <int, hits>,
  "items": [
    { "repo": "...", "file": "...", "dork": "...", "redacted_snippet": "..." }
  ],
  "notes": [...],
  "output_files": ["<absolute paths>"]
}
```

## Phase procedure
```
python3 GitDorker.py -tf targets.txt -d dorks.txt -q "<company/domain>" -token $GITHUB_TOKEN -o github_output
```
(`obheda12/GitDorker` — see `skills/seeds/github-recon.md` for the manual
dork list this pulls from if GitDorker itself isn't installed; in that
case fall back to a handful of the highest-signal dorks run manually
through the GitHub code-search API and note the reduced coverage.)

A hit that looks like a live credential (API key, private key block,
connection string) is high-priority: it's immediately testable evidence,
not a hypothesis. Route it to the falsifier/validator stages directly
rather than waiting on hypothesis generation to rediscover it from the
recon summary.
