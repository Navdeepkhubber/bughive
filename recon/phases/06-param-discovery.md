## Dependencies
Runs after: 04

# Recon Phase: 06-param-discovery

## Workspace
Write all output to the absolute path passed in the prompt
(`~/.dsh/hunts/<domain>/recon/06-param-discovery/`). Use absolute paths in your
`output_files` array. Do not write anywhere else.

## Input
Output of previous phase (or root domain for phase 01).
If a `scope.txt` exists in your working directory, read it first — treat
every hostname not listed there as out-of-scope.

## Timeout contract
Every external command MUST be wrapped in `timeout`. Suggested budgets:
- subfinder: 60s
- amass passive: 120s
- dig per host: 10s
- nmap top-1000: 300s
- httpx batch: 60s
- ffuf/feroxbuster: 180s
If a tool exceeds its budget, record it under `tools_skipped` with
reason `timeout` and continue. Never block the phase on one slow source.

## Steps
1. Read the phase-specific procedure below.
2. Run tools in parallel where safe.
3. Deduplicate results.
4. Write raw output to the phase directory.
5. Write `summary.json` to the same directory.
6. Return ONLY the JSON summary (shape below). No prose.

## Output contract
{
  "phase": "06-param-discovery",
  "domain": "<root domain>",
  "tools_run": [...],
  "tools_skipped": [{ "tool": "...", "reason": "..." }],
  "count": <int>,
  "items": [...],
  "notes": [...],
  "output_files": ["<absolute paths>"]
}

## Phase procedure
Discover hidden parameters. Prefer arjun; fall back to paramspider; if neither, skip and note. Run against URLs from phases 04 and 05 that returned 200.
