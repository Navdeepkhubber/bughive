## Dependencies
Runs after: none

# Recon Phase: 01-subdomain-enum

## Workspace
Write all output to the absolute path passed in the prompt
(`~/.dsh/hunts/<domain>/recon/01-subdomain-enum/`). Use absolute paths in your
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
  "phase": "01-subdomain-enum",
  "domain": "<root domain>",
  "tools_run": [...],
  "tools_skipped": [{ "tool": "...", "reason": "..." }],
  "count": <int>,
  "items": [...],
  "notes": [...],
  "output_files": ["<absolute paths>"]
}

## Phase procedure
Passive subdomain enumeration. subfinder (default, passive sources only), optional amass -passive. NO active resolution. Partition discovered hostnames into in_scope_confirmed / in_scope_missing / out_of_scope_found against scope.txt. Never probe or resolve any host in this phase.
