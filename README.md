# bughive

Bug-bounty research pipeline. It records what it tested and emits a finding only when a pinned rule matches live evidence.

A run with no findings is a clean result only when the stats line shows rules loaded, a live target, and requests made. `0 rules` or `0 live targets` is a broken pipeline. `decide` still needs `TYPESAFE_API_KEY` for the planner. Confirmed findings do not.

## Run a scan

Scope comes from `hunts/<domain>/scope.txt`. Active checks run only against those hosts. State-changing proofs run on loopback unless `BUGHIVE_ACTIVE_PROOF=1`.

```bash
bash scripts/pipeline/run.sh init 127.0.0.1 "127.0.0.1"
# start the local benchmark (loopback only)
node plugins/dsh-eval/fixture-app.mjs --port 8099
bash scripts/pipeline/run.sh scan 127.0.0.1 http://127.0.0.1:8099
```

Directly:

```bash
node plugins/dsh-scan/cli.mjs --base http://127.0.0.1:8099 --scope-text 127.0.0.1 --out hunts/127.0.0.1
node plugins/dsh-scan/cli.mjs --validate
```

`--validate` loads the pinned pack and exits `2` when zero rules load or a rule is invalid. It does not send requests.

Exit `2` means the pipeline did not scan (no rules, no live target, out of scope, invalid pack). Exit `1` means a check threw. Exit `0` means the scan finished, including a real "no results" run.

Other useful entry points:

```bash
npm run test:accuracy          # fixture scan, accuracy gates, report fetcher is separate
python3 -m unittest tests/test_report_fetch.py
npm run fetch                  # disclosed HackerOne reports; needs H1_API_USERNAME and H1_API_TOKEN
```

The public HackerOne scrape is best-effort. An HTTP or GraphQL error fails the process instead of looking like an empty feed. Without an API token, nothing new is downloaded.

## Read the output

Written under the `--out` directory (the hunt directory for `run.sh scan`):

| File | What it is |
|---|---|
| `findings.sarif` | SARIF 2.1.0. `results` is `[]` when nothing matched. The invocation still records rules, requests, and errors. |
| `findings.jsonl` | One `MODULE` event per external tool, then one object per finding, then a final `{"type":"run","stats":...}` line. Present even when there are no findings. |
| `validated.json` | Confirmed findings only (`status: verified`). |
| `findings.json` | Confirmed and unverified together. |
| `scan-summary.json` | Verdict plus every check: `verified`, `miss`, `skipped`, `unverified`, or `error`. |

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

Nuclei, TruffleHog, and osv-scanner are optional unmodified subprocesses (`plugins/dsh-scan/modules.js`). TruffleHog and BBOT are AGPL-3.0 and are not vendored or wrapped as a service. Semgrep registry rules and the CodeQL CLI are not included. Staged files under `skills/staging/` stay there until they are rewritten; the new seeds are original and do not contain harvest text.

HackerOne API tokens and `TYPESAFE_API_KEY` are read from the environment. Do not commit them.
