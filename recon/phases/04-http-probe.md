## Dependencies
Runs after: 03

# Recon Phase: 04-http-probe

## Workspace
Write all output to the absolute path passed in the prompt
(`~/.dsh/hunts/<domain>/recon/04-http-probe/`). Use absolute paths in your
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
  "phase": "04-http-probe",
  "domain": "<root domain>",
  "tools_run": [...],
  "tools_skipped": [{ "tool": "...", "reason": "..." }],
  "count": <int>,
  "items": [...],
  "notes": [...],
  "output_files": ["<absolute paths>"]
}

## Phase procedure
Probe every in-scope host over HTTPS (and HTTP if the port scan showed 80
open), **and** on the common alt-HTTP ports the port scan found open
(3000, 5000, 7001, 7002, 8000, 8008, 8009, 8080, 8081, 8082, 8088, 8181,
8443, 8880, 8888, 9000, 9090, 9443, 10000 — pulled from real-world bug
bounty methodology, not just the top-1000 default; admin panels, Jenkins,
and dev servers live here). Prefer httpx (`-p 80,443,3000,...`); fall back
to curl -sI per port. Capture status, title, server header, content-type,
TLS cert CN/SAN/issuer, redirect chain.
