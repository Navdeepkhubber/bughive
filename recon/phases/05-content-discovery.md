## Dependencies
Runs after: 04

# Recon Phase: 05-content-discovery

## Workspace
Write all output to the absolute path passed in the prompt
(`~/.dsh/hunts/<domain>/recon/05-content-discovery/`). Use absolute paths in your
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
  "phase": "05-content-discovery",
  "domain": "<root domain>",
  "tools_run": [...],
  "tools_skipped": [{ "tool": "...", "reason": "..." }],
  "count": <int>,
  "items": [...],
  "notes": [...],
  "output_files": ["<absolute paths>"]
}

## Phase procedure
Before fuzzing: strip any URL whose path ends in a static-asset extension
(jpg, jpeg, jfif, png, gif, bmp, tif, tiff, ico, svg, webp, avif, heic,
woff, woff2, ttf, otf, eot, css, scss, less, mp3, mp4, m4a, m4v, avi, mov,
wmv, flv, webm, ogg, ogv, wav) from the URL list before running ffuf --
these can't carry vulnerabilities and just burn fuzzing budget.

Three parallel passes feed the same de-duplicated endpoint list --
active crawling, brute-force fuzzing, and passive crawling each surface
different things and none substitutes for another:

1. **Active crawling** -- katana, following links/JS/forms rather than
   guessing paths:
   `katana -list webapps -d 5 -s breadth-first -jc -jsl -kf all -iqp -ct 10m -timeout 10 -retry 1 -p 5 -c 20 -rl 100 -hrl 20 -silent -o katana_output`
2. **Fuzzing** -- ffuf (`-recursion -recursion-depth 2` so nested
   directories get discovered too, not just the first level); fall back
   to feroxbuster; if neither, skip and note. Wordlist:
   recon/wordlists/files.txt. Only 200, 301, 302, 401, 403 responses.
3. **Passive crawling** -- urlfinder (ProjectDiscovery) for
   already-indexed URLs/JS/endpoints without touching the target:
   `urlfinder -list domains -all -silent -o urlfinder_output`; fall back
   to gau/waybackurls if urlfinder isn't installed.

Merge and de-duplicate all three outputs into the phase's `items[]`.
