# AGENTS.md — bughive Operating Manual

You are the parent orchestrator of a bug bounty hunt. The pipeline is
implemented as shell scripts under `scripts/pipeline/`. Call them via the
Bash tool.

## Keeping your own context clean

Every stage marked **[SUBAGENT]** below must be delegated to a subagent
(spawn one via your platform's subagent-spawning tool) rather than reasoned
through inline in your own conversation. Recon (Stage 1) already does this
correctly via `run_recon_phase` (see Plugin tools below) or the bash
scripts, which write their findings to disk and return only a small JSON
summary -- your context never holds a phase's raw output. Stages 3, 5, and
9 did NOT follow this pattern before and were rewritten to: each of them
can involve reading tens of KB of skill checklists and recon data, and if
that reasoning happens in the parent's own context, it stays there --
bloating every subsequent stage in the same hunt with dead weight, and
defeating the entire point of using subagents. A stage marked **[TOOL]**
has a real deterministic plugin tool built for it; call the tool, don't
re-implement its logic ad hoc.

## Plugin tools

- `pre_validation_filter` (dsh-fp-filter) -- **[TOOL]**, Stage 4.
- `validate_finding` (dsh-finding-validator) -- **[TOOL]**, Stage 6. Real
  transport layer (ctx.web seam + curl fallback), never throws -- inspect
  the returned `error`/`confidence` fields.
- `run_recon_phase` (dsh-recon-orchestrator) -- **[TOOL]**, Stage 1, if your
  environment prefers this over calling the bash scripts directly. Spawns
  a real subagent per phase via `ctx.subagents.start()`.
- `build_chain` (dsh-chain-builder) -- **[TOOL]**, Stage 7.
- `write_report` (dsh-report-writer) -- **[TOOL]**, Stage 8.

  These five were broken as of the last audit (`ctx.sessions.create().run()`
  doesn't exist on the installed DSH API) and are now fixed and verified --
  `node plugins/_selftest.mjs` passes 21/21 against the real files, not
  mocks. See `plugins/PLUGIN-FIXES.md` for the full API citation trail.

Every other plugin (dsh-observability, dsh-hunt-state, dsh-skill-admission,
dsh-h1-classifier, etc.) is background observability/skill-management
infrastructure and should not be invoked directly.

## Rules
1. Never run tools outside scope.txt.
2. Wait for each serial stage to fully return before starting the next.
3. Report progress using `hunt_mark` after every stage.
4. Stop and report if any stage fails.
5. A `critical` or `high` hit from Stage 1's phase 14 (nuclei) or phase 15
   (mass-oneliners) should be flagged for human-gate review immediately,
   not left to wait behind the rest of the pipeline -- see Stage 3.

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

Then run these concurrently (fire all, do not wait between calls) -- 14
and 16 only depend on 04 and 01 respectively, so they join this batch
rather than waiting for phases they don't need:

    bash scripts/pipeline/run.sh recon-05 <domain>
    bash scripts/pipeline/run.sh recon-06 <domain>
    bash scripts/pipeline/run.sh recon-07 <domain>
    bash scripts/pipeline/run.sh recon-08 <domain>
    bash scripts/pipeline/run.sh recon-09 <domain>
    bash scripts/pipeline/run.sh recon-14 <domain>
    bash scripts/pipeline/run.sh recon-16 <domain>

Then:

    bash scripts/pipeline/run.sh recon-10 <domain>

Then, since it needs 05/06's merged endpoint list:

    bash scripts/pipeline/run.sh recon-12 <domain>

Then these three concurrently (all only need phase 12's cache, or in
17's case, phase 06's endpoint list):

    bash scripts/pipeline/run.sh recon-13 <domain>
    bash scripts/pipeline/run.sh recon-15 <domain>
    bash scripts/pipeline/run.sh recon-17 <domain>

Then last, since it depends on 04/05/06/07's output for candidate entry
URLs and executes real (safety-gated) multi-step flows rather than static
probes:

    bash scripts/pipeline/run.sh recon-11 <domain>

Phases 12-17 are the "proven methodology" additions: 12 caches every
response body locally (so 13/15 can grep a local file instead of
re-hitting the live target per check); 13 scans that cache for secrets;
14 runs nuclei for template-confirmed low-hanging fruit; 15 runs
deterministic XSS/SSRF/SSTI/CORS one-liners across the whole endpoint
corpus with zero LLM tokens; 16 runs automated GitHub dorking (the
existing `github-recon.md` skill had nothing that actually executed it
before this); 17 flags interesting-looking endpoints (/admin, /api/,
/graphql, /debug, /swagger, /internal, /openapi, /actuator) by keyword so
the hypothesis stage doesn't have to rediscover priority targets from a
flat list at LLM-token cost.

### Stage 2 — skill selection

 bash scripts/pipeline/run.sh skills <domain>

Deterministically scores every skill in skills/seeds/ and skills/learned/
against the recon corpus (now including phases 12-17) and writes
hunts/<domain>/skills-selected.json, each entry showing its score and
matched evidence terms. This is evidence for the decision stage, not the
decision itself. This must run before Stage 2.5.

### Stage 2.5 — JEV decide **[TOOL]**

 bash scripts/pipeline/run.sh decide <domain>

JEV (TypeSafe System One, `https://api.typesafe.ai/v1/systemone`) does not
write text. It reads the recon summaries plus the skill catalog and returns
typed answers with probabilities. `scripts/pipeline/jev-decide.mjs` applies
hunt policy on top of those answers and writes
hunts/<domain>/jev-decision.json. Requires `TYPESAFE_API_KEY` (a `.env`
file in the repo root is read if the variable is unset). Optional
`TYPESAFE_MODEL` (default `jev-latest`).

The file's `next_action` is binding. Do not re-pick the skill, the
vulnerability, or the test method in your own reasoning. Re-run `decide`
before choosing any later stage; the same script reclamps against whatever
artifacts exist now.

| `next_action` | What you do |
|---|---|
| `deepen_recon` | Run the single phase in `recon_phase`, then `decide` again |
| `select_and_test` | Stage 3, only for `skill` / `vuln`, `test_method`, and `focus_url` |
| `falsify` | Stages 4 and 5 |
| `prove` | Stage 6 |
| `chain` | Stage 7 |
| `report` | Stages 8 and 9 |
| `human_gate` | Stop and report the decision to the user |
| `stop` | Stage 10 |

Policy the script enforces, so you don't: confidence below 0.45 or
`human_review` above 0.7 becomes `human_gate`; a critical or high nuclei
hit, or any phase-15 one-liner hit, becomes `human_gate` before hypotheses
exist; an action that names artifacts that do not exist yet is moved
forward to the earliest legal stage; a skill is loaded only when its
confirm probability is at least 0.4. Keyword scores are copied to
`skills-keyword.json`. The skills Stage 3 actually loads are the JEV
keep-list rewritten into `skills-selected.json`.

One question in that call is "which skill", one is "which vulnerability
among the top three", one is "how to test" (`checklist_walk`,
`tool_hit_falsify`, `flow_step_skip`, `auth_swap`, `param_mutation`,
`version_match`, `hold`). JEV picks inside that closed set. It does not
invent payloads.

### Stage 3 — hypothesis **[SUBAGENT]**

    bash scripts/pipeline/run.sh hypothesis <domain>

This writes hunts/<domain>/hypothesis-prompt.txt. Spawn a subagent with
that file's full content as its prompt; it writes
hunts/<domain>/hypotheses.json and returns you only a short confirmation
(count written, top priorities) -- not the full reasoning trace. Do not
read hypothesis-prompt.txt into your own context and reason through it
yourself; that file can run to ~140KB (skill checklists + recon data) and
has no reason to live in the parent's context for the rest of the hunt.

The prompt requires every hypothesis to cite a specific recon item and a
specific technique from one of the selected skills -- no evidence, no
hypothesis -- EXCEPT tool-confirmed hits from phases 13/14/15/16, which
the prompt itself instructs the subagent to pass through directly at
priority 9-10 rather than re-deriving.

### Stage 4 — prefilter **[TOOL]**

Call the `pre_validation_filter` tool (dsh-fp-filter) per hypothesis to
drop anything out of scope, lacking a baseline, or referencing empty
recon. Write survivors to hunts/<domain>/hypotheses-pass.json.

### Stage 5 — falsifier **[SUBAGENT]**

Spawn a subagent per batch of survivors (or one subagent for the whole
batch if it fits comfortably in its context) with the survivors list and
this task: look for concrete false-positive signals -- scheme-mismatch
redirects, WAF pages, wrong-product matches, placeholder values, auth-wall
false positives -- and emit {verdict, confidence, signals} per hypothesis.
Keep only verdict==true AND confidence>=0.6 in hypotheses-real.json. This
is the stage most likely to see a nuclei/oneliner template false-positive,
so give it the raw recon evidence for those hits, not just the hypothesis
summary.

### Stage 6 — proof validator **[TOOL]**

For each survivor, craft the minimal deterministic payload and call the
`validate_finding` tool (dsh-finding-validator) with baseline + probe. It
never throws -- a network/parse failure comes back as
`{validated:false, error:{code, message}}`, not an exception. On success
it reports the raw `diff` (statusChanged/lengthDelta/bodyDiffers, for
compatibility) plus noise-aware `confidence`
(high/medium/low-likely-noise/none) and `normalizedBodyDiffers` -- treat
`confidence: "low-likely-noise"` as not actually validated even though the
raw `diff` fired, since that combination means the only difference found
was timestamp/token noise. Per-finding evidence lands wherever the tool's
`finding/validation` event routes it; collect the validated list into
hunts/<domain>/validated.json.

### Stage 7 — chain **[TOOL]**

Call the `build_chain` tool (dsh-chain-builder) with the validated
findings as a JSON array. It reads every playbook in playbooks/ itself and
returns the proposed A-to-B-to-C chain text directly -- write that to
hunts/<domain>/chains.json yourself; the tool no longer writes to disk on
its own (see PLUGIN-FIXES.md §2.4 for why that changed).

### Stage 8 — report **[TOOL]**

Call the `write_report` tool (dsh-report-writer) once per validated
finding, passing the finding and (if one exists) its chain. It returns the
HackerOne-format markdown text directly -- write it yourself to
hunts/<domain>/reports/report-<id>.md. Sections: Title, Severity, Summary,
Steps to Reproduce, Impact, Remediation, Evidence.

### Stage 9 — quality gate **[SUBAGENT]**

Spawn a subagent per report (or batch a few small ones together) with:
check required sections, scan for placeholders, verify numbered steps
contain concrete artifacts, verify severity matches impact. Copy passing
reports to hunts/<domain>/reports/approved/. (Note: this checklist is
mechanical enough that it's a reasonable future candidate for a real
deterministic tool like `pre_validation_filter`, rather than needing a
model at all -- nobody has built that yet.)

### Stage 10 — deliver

Write hunts/<domain>/SUMMARY.md with recon counts, validated findings,
approved reports. Report the summary to the user.

## Paths

- Workspace: current directory (bughive)
- Hunt artifacts: hunts/<domain>/
- Skills: skills/seeds/ + skills/learned/
- Playbooks: playbooks/

## Model

DeepSeek V4.1 Flash for generation. Reasoning effort is tuned per stage
rather than uniformly high (see each plugin's `cordis.patch.yml`): recon
phases (dsh-recon-orchestrator) default to `low` -- they follow a fixed,
documented procedure with little open-ended reasoning. `write_report`
defaults to `medium`. `build_chain` and the hypothesis/falsifier subagents
stay `high`, since matching evidence against skill checklists and
proposing exploit chains is exactly the kind of reasoning that budget is
for.

JEV is the decision layer in front of that. It chooses the next stage, the
skill, the vulnerability, and the test method. DeepSeek still writes
hypotheses, chains, and reports inside the choice JEV already made.
