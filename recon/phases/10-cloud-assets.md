## Dependencies
Runs after: 01

# Recon Phase: 10-cloud-assets

## Workspace
Write all output to the absolute path passed in the prompt
(`~/.dsh/hunts/<domain>/recon/10-cloud-assets/`). Use absolute paths in your
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
  "phase": "10-cloud-assets",
  "domain": "<root domain>",
  "tools_run": [...],
  "tools_skipped": [{ "tool": "...", "reason": "..." }],
  "count": <int>,
  "items": [...],
  "notes": [...],
  "output_files": ["<absolute paths>"]
}

## Phase procedure
Cloud asset enumeration. S3 buckets, GCP buckets, Azure blobs related to the domain. Prefer cloud_enum/s3scanner; if neither, check public DNS TXT records for cloud service references and note the limitation.
