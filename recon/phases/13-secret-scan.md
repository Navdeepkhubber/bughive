## Dependencies
Runs after: 07, 12

# Recon Phase: 13-secret-scan

## Workspace
Write all output to the absolute path passed in the prompt
(`~/.dsh/hunts/<domain>/recon/13-secret-scan/`). Use absolute paths in your
`output_files` array. Do not write anywhere else.

## Input
The response cache from phase 12 (`recon/12-response-cache/`) plus the
downloaded JS files from phase 07. If a `scope.txt` exists, read it first.

## Timeout contract
- Whole phase: 10 minutes wall-clock
- Per-tool budget: trufflehog/gitleaks/kingfisher 3 minutes each; the
  custom `rg` regex pass is fast (seconds) and has no separate budget

## Steps
1. Run the three general-purpose secret scanners against the phase-12
   cache directory and the phase-07 downloaded JS.
2. Run the custom regex pass for auth headers / API keys.
3. Separately flag any Google API keys found and validate what they can
   access (never exploit -- see below).
4. De-duplicate hits across all four tools by (file, line, matched string).
5. Write `summary.json`. Return ONLY the JSON summary.

## Output contract
```json
{
  "phase": "13-secret-scan",
  "domain": "<root domain>",
  "tools_run": ["trufflehog", "gitleaks", "kingfisher", "rg"],
  "tools_skipped": [{ "tool": "...", "reason": "..." }],
  "count": <int, deduped secret hits>,
  "items": [
    { "tool": "...", "file": "...", "line": <int>, "rule": "...", "redacted_match": "...", "confidence": "..." }
  ],
  "notes": [...],
  "output_files": ["<absolute paths>"]
}
```
`redacted_match` MUST be truncated/masked (e.g. first 6 + last 4 chars) --
never write a live, usable secret verbatim into a JSON file another
process might display.

## Phase procedure
1. **General scanners**: run `trufflehog filesystem <cache-dir>`,
   `gitleaks detect --source <cache-dir> --no-git`, and `kingfisher scan
   <cache-dir>` (whichever are installed; skip and note the rest).
2. **Custom regex pass** against the cached response bodies for
   Basic/Bearer tokens and generic API-key-shaped strings, e.g.:
   `rg -n --hidden -i 'Basic[[:space:]]+([A-Za-z0-9_=\\+/-]{10,})|Bearer[[:space:]]+([A-Za-z0-9._~+/-]{20,})' <cache-dir>`
3. **Google API keys**: grep for the `AIza[0-9A-Za-z_-]{35}` shape
   specifically, then run `agneyastra` (or note it's unavailable) against
   each match to report which Google APIs the key can reach -- this is a
   read-only capability check, not exploitation; never call a
   state-changing Google API with a found key.
4. Redact every match before writing to `summary.json` (see contract
   above). If the caller wants the full value to build a validated finding
   later, it stays in the raw scanner output files under this phase's
   directory (still local-only, still gitignored), not in the JSON summary
   that feeds the hypothesis prompt.
