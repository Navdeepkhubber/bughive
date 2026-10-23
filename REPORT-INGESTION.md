# Disclosed report ingestion

`.github/workflows/fetch-reports.yml` runs weekly and can also be started with
`workflow_dispatch`. Configure the repository secrets `H1_API_USERNAME` and
`H1_API_TOKEN` with HackerOne API credentials. The workflow fails with a clear
error if either secret is missing or the API request fails.

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
