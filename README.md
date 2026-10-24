# bughive

Bug-bounty research pipeline. It records what it tested and emits a finding only when a pinned rule matches live evidence.

A run with no findings is a clean result only when the stats line shows rules loaded, a live target, and requests made. `0 rules` or `0 live targets` is a broken pipeline. `scan` and confirmed findings run with no `TYPESAFE_API_KEY`. With no key and no `BUGHIVE_PLANNER` override, `decide` uses the local heuristic planner.

## Getting started

### Prerequisites

- Node.js 20 or newer (`engines` in `package.json`).
- `python3` for `fetch` and `harvest`. The local scan is Node only. `harvest` also needs `git`.

### Install

```bash
npm install
npx playwright install chromium   # optional; recon phase 11 (flow mapping)
```

`npm install` installs `playwright` and `yaml`. The fixture scan uses Node built-ins. Chromium is a separate download. Without it, recon phase 11 records `degraded: true` and skips flow execution. `postinstall` prints the same `npx` command.

### Environment

Every variable in `.env.example` is optional. The fixture scan below runs with none of them set.

```bash
cp .env.example .env
```

| Variable | Required? | Used by |
|---|---|---|
| `H1_API_USERNAME` | Optional. Both this and `H1_API_TOKEN` must be set to call the HackerOne API. | `fetch` |
| `H1_API_TOKEN` | Same pair. Create one at https://hackerone.com/settings/api_token/edit | `fetch` |
| `BOUNTY_ALERT_WEBHOOK` | Optional. | Bounty-budget alert webhook (`plugins/dsh-bounty-budget/cordis.patch.yml`) |

`fetch` reads `H1_API_USERNAME` and `H1_API_TOKEN` from the process environment. A copied `.env` is not loaded by `run.sh fetch`. Export them, or source the file the way the off-peak cron does:

```bash
set -a
source .env
set +a
```

Planner variables are optional. They are not listed in `.env.example`.

- No `TYPESAFE_API_KEY` selects the local heuristic. That is the default for `decide` and `loop`.
- `BUGHIVE_PLANNER=heuristic` keeps the local planner when a key is set. `local` and `policy` select the same mode.
- `BUGHIVE_PLANNER=jev` selects the remote TypeSafe planner and requires `TYPESAFE_API_KEY`. `typesafe` selects the same mode.
- With `BUGHIVE_PLANNER` unset and `TYPESAFE_API_KEY` set, `decide` uses the remote planner.
- `decide` reads `TYPESAFE_API_KEY` from the environment. When that variable is unset, it reads a `TYPESAFE_API_KEY=` line from `.env`. It leaves every other line in that file alone.
- `TYPESAFE_MODEL` defaults to `jev-latest`. `TYPESAFE_API_BASE` overrides the API URL.

`scan` and confirmed findings ignore the planner. `BUGHIVE_ACTIVE_PROOF=1` allows state-changing proofs off loopback. Leave it unset for the fixture.

### First run

The fixture app is the intentionally vulnerable local stand-in. It binds `127.0.0.1` only. The default port is `8099`.

```bash
bash scripts/pipeline/run.sh init 127.0.0.1 "127.0.0.1"
node plugins/dsh-eval/fixture-app.mjs --port 8099
```

Leave the fixture in that terminal. In another shell:

```bash
bash scripts/pipeline/run.sh scan 127.0.0.1 http://127.0.0.1:8099
```

`init` writes `hunts/127.0.0.1/scope.txt`. `scan` exits if that file is missing. Results are written under `hunts/127.0.0.1/`.

### Other entry points

```bash
bash scripts/pipeline/run.sh fetch             # disclosed HackerOne reports
bash scripts/pipeline/run.sh fetch --dry-run   # prints a line; does not call the API
bash scripts/pipeline/run.sh harvest           # clone skills/sources.txt into skills/staging/
bash scripts/pipeline/run.sh harvest --dry-run
bash scripts/pipeline/run.sh ingest-skills     # promote staging into skills/learned/ and missing seeds
bash scripts/pipeline/run.sh ingest-skills --dry-run
npm test                   # tests/*.test.mjs, then the fetch/harvest unittest modules
npm run test:accuracy     # node --test tests/*.test.mjs
npm run test:fetch        # python3 -m unittest tests/test_report_fetch.py tests/test_harvest.py
```

`npm run fetch` is the same Python script as `run.sh fetch`. Install its dependency with `pip install -r intelligence/requirements.txt` (`requests`). `--dry-run` still imports that package. Without `H1_API_USERNAME` and `H1_API_TOKEN`, API mode is skipped. `--dry-run` on `harvest` and `ingest-skills` writes nothing. A public HTTP or GraphQL error raises instead of returning zero. `fetch` exits 1 when every mode fails, and it prints those errors.

## Run a scan

Scope comes from `hunts/<domain>/scope.txt`. Active checks run only against those hosts. State-changing proofs run on loopback unless `BUGHIVE_ACTIVE_PROOF=1`.

The same scan, without `init`:

```bash
node plugins/dsh-scan/cli.mjs --base http://127.0.0.1:8099 --scope-text 127.0.0.1 --out hunts/127.0.0.1
node plugins/dsh-scan/cli.mjs --validate
```

`--validate` loads the pinned pack and exits `2` when zero rules load or a rule is invalid. It does not send requests.

Exit `2` means the pipeline did not scan (no rules, no live target, out of scope, invalid pack). Exit `1` means a check threw. Exit `0` means the scan finished, including a real "no results" run.

## Read the output

Written under the `--out` directory (the hunt directory for `run.sh scan`):

| File | What it is |
|---|---|
| `findings.sarif` | SARIF 2.1.0. `results` is `[]` when nothing matched. The invocation still records rules, requests, and errors. |
| `findings.jsonl` | One `MODULE` event per external tool, then one object per finding, then a final `{"type":"run","stats":...}` line. Present even when there are no findings. |
| `validated.json` | Confirmed findings only (`status: verified`). |
| `findings.json` | Confirmed and unverified together. |
| `scan-summary.json` | Verdict plus every check: `verified`, `miss`, `skipped`, `unverified`, or `error`. |
| `scan-history.jsonl` | One line per scan. Later runs append. The line has counts and module status, not request bodies. |

`status` is `verified`, `unverified`, or `verification_skipped`. Unverified rows stay out of `validated.json`. A verified row has a saved request and response (or the verifier's own output). The fingerprint is `sha256(skill_id + asset + evidence_hash)`.

`scan-summary.json` → `stats.modules` says `not-installed` when Nuclei, TruffleHog, osv-scanner, or BBOT are absent. That is a skipped module, not a clean result for it. When the binary is on PATH it is executed, and the JSONL `MODULE` line says `ran`, `error`, or `skipped`. Nuclei runs only against loopback, or anywhere in scope when `--active 1` or `BUGHIVE_ACTIVE_PROOF=1` is set. A non-zero exit with empty output is a module error. osv-scanner replaces the api.osv.dev query when it exits successfully; if it is missing or errors, the API query still runs. BBOT is reported and not started.

## Rules and canaries

Rules live in `plugins/dsh-scan/pack.js` (`bughive-rules` 1.1.0). They use the Nuclei shape — id, severity, requests, matchers, extractors, flow — and are original. `flow` is the request order. Extractors are recorded on a hit and cannot by themselves confirm one. Loading zero rules fails the run.

```bash
node --test tests/scan.test.mjs tests/canaries.test.mjs
```

The canaries that must hit:

- Local login tautology (`canaries/juice-login.mjs`), the same bug class as the Juice Shop login floor. It is not Juice Shop and does not contain its code.
- `canaries/lockfile/package.json` pins `lodash@4.17.20`. A live `api.osv.dev` query must return `GHSA-35jh-r3h4-6jhm`.
- `canaries/secrets/keys.txt`: `AKIAIOSFODNN7EXAMPLE` is ignored; a non-example key is reported `unverified`, never confirmed.
- `expired.badssl.com` must be confirmed `CERT_HAS_EXPIRED`.
- A certificate this repo revokes locally must be confirmed by `openssl verify -crl_check`.

`revoked.badssl.com` is checked every time. On 2026-10-23 its leaf was a current Let's Encrypt certificate, so the run records `verification_skipped` instead of a revoked finding. A hostname is not evidence of revocation.

## What was borrowed, and what was not copied

| Source | Used |
|---|---|
| Nuclei | Matcher shape, `flow` and extractors, a `--validate` step, and the unmodified `nuclei -jsonl` CLI when it is installed. No template pack is copied in. |
| TruffleHog | `verified` / `unverified` / `verification_skipped`, via the unmodified `trufflehog filesystem --json` CLI. Unverified is never confirmed. The raw secret is not stored. |
| BBOT | Typed `MODULE` / `FINDING` / `VULNERABILITY` events. Nuclei, TruffleHog, and osv-scanner are subprocess modules. BBOT itself is not started. |
| OSV-Scanner | Unmodified `osv-scanner scan source --lockfile … --format json` when installed. Otherwise the public OSV API. Advisory bodies stored are id, summary, and aliases only. |
| Gitleaks | Example-key allowlist and a report that still exists when empty. |
| Strix / pentest-harness | A finding without a saved exchange is not confirmed. The run log is written even when the result is empty, so a step cannot vanish. No agent or UI code was copied. |

Nuclei, TruffleHog, and osv-scanner are optional unmodified subprocesses (`plugins/dsh-scan/modules.js`). TruffleHog and BBOT are AGPL-3.0 and are not vendored or wrapped as a service. Semgrep registry rules and the CodeQL CLI are not included.

## Weekly sync and skill promotion

`.github/workflows/sync-reports-and-skills.yml` is the only scheduled workflow. Sunday 06:00 UTC, and `workflow_dispatch` with `task` (`all`, `fetch`, `harvest`, `ingest-skills`) and `dry_run`.

| Job | Command | Result |
|---|---|---|
| `fetch` | `bash scripts/pipeline/run.sh fetch` | Disclosed HackerOne reports. Needs `H1_API_USERNAME` and `H1_API_TOKEN`. `--dry-run` does not call the API. |
| `harvest` | `bash scripts/pipeline/run.sh harvest` | Clones `skills/sources.txt` into `skills/staging/`. Header records repo, path, author, license, commit, and fetch date. AGPL and GPL repos are skipped. Other non-permissive repos are flagged and still staged so ingest can derive house text. |
| `ingest-skills` | `bash scripts/pipeline/run.sh ingest-skills` | Promotes staging into `skills/learned/` and creates a seed only when `skills/seeds/` has none for that class. |

`harvest` waits for `fetch`. `ingest-skills` waits for both. A failed fetch does not block promotion. `--dry-run` on any of the three writes nothing. Journal ingest is still `run.sh ingest` and is a different command.

The loader reads `skills/seeds/` and `skills/learned/` only. Staging stays the raw cache. Of the current 118 staged files, 30 map to one class and 88 are flagged `no-class` in `skills/ingest-report.json`. 29 promoted skills are original house-style text because their repos have no permissive license. The one MIT file (`Aetherdz/huntpack` business-logic) is copied with its copyright line. New seeds are `file-upload`, `rce`, and `saml`. Existing seeds are not overwritten. A confirmed finding can list `coveredBy` skill ids. The skill file is not itself the proof.

## Reference repos

These were read as structure, not as code to paste. Proof rules did not change: a confirmed finding still needs a saved request and response, or a verified API result, and active checks still need `scope.txt`.

| Repo | Kept | Left out |
|---|---|---|
| [pentest-harness](https://github.com/S1N6H/pentest-harness) (MIT) | A run log that is not thrown away, and a misconfiguration that fails the process instead of looking like an empty result. Credentials stay out of the log. | The Cordis UI, plugin tree, and agent runtime. This repo already has its own plugin host. |
| [Bug-Bounty-Skills](https://github.com/S1N6H/Bug-Bounty-Skills) (pipeline MIT; skill text is not) | Content-hash dedupe, `owner-repo-path` filenames, and a license hint on each staged file. A failed harvest exits non-zero. | The aggregator source list. Third-party prose is loaded only when the source license is permissive; otherwise the learned skill is original house text. |
| [S1N6H-Recon](https://github.com/S1N6H/S1N6H-Recon) (no license) | The idea that several passive sources should be unioned, then marked when a tool is missing. Phase 01 already calls subfinder and amass as argv, then scope-filters. It now sets `degraded: true` when neither tool ran. | The script itself. It interpolates the domain into `shell=True`, prints "finished" before the processes exit, has no scope check, and has no license. |
| [Barcha](https://github.com/S1N6H/Barcha) (MIT) | Append-only scan history, and the existing rule that a TLS error means the host is up. | Shodan wildcard enumeration and `ghauri --dump` against discovered hosts. That is exploitation without a per-host scope decision. |
| [Pentest-AI-BurpSuite](https://github.com/S1N6H/Pentest-AI-BurpSuite) (MIT) | Claims cite a saved exchange. The scan history line does not invent findings. | The Burp agent, the jar, and a tool loop that sends arbitrary requests from model output. |

HackerOne API tokens and `TYPESAFE_API_KEY` are optional. `fetch` reads the HackerOne pair from the environment. `decide` reads `TYPESAFE_API_KEY` from the environment, or from a `.env` line when that variable is unset. `.env` is gitignored. Do not commit either secret.
