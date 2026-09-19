## Dependencies
Runs after: 04

# Recon Phase: 14-nuclei-scan

## Workspace
Write all output to the absolute path passed in the prompt
(`~/.dsh/hunts/<domain>/recon/14-nuclei-scan/`). Use absolute paths in your
`output_files` array. Do not write anywhere else.

## Input
The de-duplicated webapp list from phase 04 (`webapps`). If a `scope.txt`
exists, read it first.

## Why this phase exists
This is the "low hanging fruit" pass: thousands of community-maintained
templates checking for known CVEs, exposed panels, default credentials,
misconfigurations, and common exposed files. Unlike the hypothesis/
validator stages, a nuclei match is already a template-confirmed finding,
not a hypothesis needing LLM-driven validation -- it goes almost directly
to the falsifier stage (mainly to catch template false-positives) rather
than through hypothesis generation. Running this early and cheaply, before
any LLM reasoning happens, is the single highest bug-yield-per-dollar step
in the whole pipeline.

## Timeout contract
- Whole phase: 20 minutes wall-clock (nuclei's own rate limiting handles
  per-request pacing)
- If nuclei isn't installed, skip and note -- do not attempt a manual
  substitute; there is no reasonable fallback for a signature database
  this size.

## Steps
1. Run nuclei against every host in `webapps`, all severities.
2. Parse nuclei's JSON output.
3. Write `summary.json`. Return ONLY the JSON summary.

## Output contract
```json
{
  "phase": "14-nuclei-scan",
  "domain": "<root domain>",
  "tools_run": ["nuclei"],
  "tools_skipped": [{ "tool": "nuclei", "reason": "not installed" }],
  "count": <int, matches>,
  "items": [
    { "template": "...", "severity": "...", "host": "...", "matched_at": "...", "description": "..." }
  ],
  "notes": [...],
  "output_files": ["<absolute path to nuclei_output>"]
}
```

## Phase procedure
```
nuclei -l webapps -severity critical,high,medium,low -jsonl -o nuclei_output
```
Parse each JSONL line into an `items[]` entry. A `critical` or `high`
match here should be flagged for immediate human-gate review even before
the rest of the pipeline finishes -- don't let it wait behind hypothesis
generation and the falsifier stage for a template that's already about as
confirmed as automated scanning gets.
