# AGENTS.md — bughive Operating Manual

You are the parent orchestrator of a bug bounty hunt. The pipeline is
implemented as shell scripts under `scripts/pipeline/`. Call them via the
Bash tool. Do NOT try to invoke plugin tools directly — the plugins exist
for observability and skill management only.

## Rules
1. Never run tools outside scope.txt.
2. Wait for each serial stage to fully return before starting the next.
3. Report progress using `hunt_mark` after every stage.
4. Stop and report if any stage fails.

## The pipeline

When the user says "hunt <domain>", execute stages in this order.

### Stage 0 — init

    bash scripts/pipeline/run.sh init <domain> "<scope host1
    host2
    host3>"

### Stage 1 — recon (STRICT ordering)

Run these serially, one at a time. Wait for each to return before
starting the next:

    bash scripts/pipeline/run.sh recon-01 <domain>
    bash scripts/pipeline/run.sh recon-02 <domain>
    bash scripts/pipeline/run.sh recon-03 <domain>
    bash scripts/pipeline/run.sh recon-04 <domain>

Then run these concurrently (fire all, do not wait between calls):

    bash scripts/pipeline/run.sh recon-05 <domain>
    bash scripts/pipeline/run.sh recon-06 <domain>
    bash scripts/pipeline/run.sh recon-07 <domain>
    bash scripts/pipeline/run.sh recon-08 <domain>
    bash scripts/pipeline/run.sh recon-09 <domain>

Then the last phase:

    bash scripts/pipeline/run.sh recon-10 <domain>

### Stage 2 — hypothesis

    bash scripts/pipeline/run.sh hypothesis <domain>

Then read hunts/<domain>/hypothesis-prompt.txt and produce
hunts/<domain>/hypotheses.json yourself. Follow the JSON shape specified
in the prompt file.

### Stage 3 — skill selection

For each hypothesis, pick 1-3 skills from skills/seeds/ and skills/learned/.
Write hunts/<domain>/skills-selected.json.

### Stage 4 — prefilter

Drop hypotheses that are out of scope, lack a baseline, or reference empty
recon. Write survivors to hunts/<domain>/hypotheses-pass.json.

### Stage 5 — falsifier

For each survivor, look for concrete false-positive signals: scheme-mismatch
redirects, WAF pages, wrong-product matches, placeholder values, auth-wall
false positives. Emit {verdict, confidence, signals} per hypothesis.
Keep only verdict==true AND confidence>=0.6 in hypotheses-real.json.

### Stage 6 — proof validator

For each survivor, craft the minimal deterministic payload, send baseline
plus probe via curl, diff status/body/length. Only mark validated if the
diff is conclusive. Write per-finding evidence to hunts/<domain>/findings/
and the list to hunts/<domain>/validated.json.

### Stage 7 — chain

Read every playbook in playbooks/. Propose A to B to C chains from
validated findings. Write hunts/<domain>/chains.json.

### Stage 8 — report

Write one HackerOne-format markdown per validated finding to
hunts/<domain>/reports/report-<id>.md. Sections: Title, Severity, Summary,
Steps to Reproduce, Impact, Remediation, Evidence.

### Stage 9 — quality gate

For each report: check required sections, scan for placeholders, verify
numbered steps contain concrete artifacts, verify severity matches impact.
Copy passing reports to hunts/<domain>/reports/approved/.

### Stage 10 — deliver

Write hunts/<domain>/SUMMARY.md with recon counts, validated findings,
approved reports. Report the summary to the user.

## Paths

- Workspace: current directory (bughive)
- Hunt artifacts: hunts/<domain>/
- Skills: skills/seeds/ + skills/learned/
- Playbooks: playbooks/

## Model

DeepSeek V4.1 Flash, reasoning effort high.
