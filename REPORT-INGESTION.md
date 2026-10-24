# Disclosed report ingestion

`.github/workflows/sync-reports-and-skills.yml` is the weekly workflow. Its
first job fetches disclosed reports. The next jobs harvest `skills/staging/`
and promote them; see `skills/staging/README.md`. Run the fetch on its own
with `bash scripts/pipeline/run.sh fetch`. `--dry-run` prints the plan and
does not call the API. Configure the repository secrets `H1_API_USERNAME`
(your HackerOne username) and `H1_API_TOKEN` (your personal Hacker API token).
The fetch job fails with a clear error if either secret is missing or the API
request fails. A failed fetch does not cancel the harvest or the promotion.

The fetcher calls the Hacker API's `GET /v1/hackers/hacktivity` endpoint for
disclosed reports. The organization `GET /v1/reports` endpoint is a different
API and does not provide the public Hacktivity feed. The first run looks back
30 days; subsequent runs use the committed cursor. Hacktivity provides report
metadata and a generated summary, not the full report body. Reports with no
useful summary may be rejected by skill admission.

To verify credentials locally without ingesting reports, set those two
environment variables and run `python3 intelligence/fetch-h1-reports.py
--check-auth`. It prints only whether authentication succeeded. Keep the token
in a secret store or your shell environment; never commit it to the repository.

The fetcher writes normalized disclosed reports to the runner's
`~/.dsh/bounty-queue/`, then the workflow commits `reports/h1-<id>.json` to the
repository. It also commits `reports/.last-fetch.json`, the API cursor used by
the next run. `reports/` contains source material, not active hunt skills.

On a machine running Bughive, `run.sh skills <domain>` copies committed reports
into that machine's `~/.dsh/bounty-queue/`. The installed DSH
`dsh-h1-classifier` plugin checks that queue each minute, creates a candidate
skill, and runs the skill admission gate. Admitted skills go to
`~/.dsh/skills/learned/h1-*.md`; rejected candidates do not enter the hunt.
Skill scoring, JEV selection, hypothesis prompts, and skill retrieval now read
admitted skills from this directory. A report first queued during skill scoring
becomes available after the classifier processes it; run skill scoring again to
include it. DSH must be running with `dsh-h1-classifier` installed for this
conversion to happen. Local paths can be redirected with `BUGHIVE_DSH_DIR`.

Verify the bridge with `python3 intelligence/sync-report-queue.py`. Its JSON
output reports how many source reports were seen, queued, already processed,
or invalid. Run `npm run test:accuracy` and
`python3 -m unittest tests/test_report_fetch.py` for offline regression checks.
