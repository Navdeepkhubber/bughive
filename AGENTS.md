# AGENTS.md — bughive Operating Manual

You are the parent executor of a bug bounty hunt. JEV decides the next
step. You run that step. The pipeline scripts live under
`scripts/pipeline/`. Call them via the Bash tool.

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

- `pre_validation_filter` (dsh-fp-filter) -- **[TOOL]**, when JEV says prefilter.
- `validate_finding` (dsh-finding-validator) -- **[TOOL]**, when JEV says prove. Real
  transport layer (ctx.web seam + curl fallback), never throws -- inspect
  the returned `error`/`confidence` fields.
- `run_recon_phase` (dsh-recon-orchestrator) -- **[TOOL]**, when JEV says
  deepen_recon, if you prefer it over the bash recon scripts. Spawns
  a real subagent per phase via `ctx.subagents.start()`.
- `build_chain` (dsh-chain-builder) -- **[TOOL]**, when JEV says chain.
- `write_report` (dsh-report-writer) -- **[TOOL]**, when JEV says report.

  These five were broken as of the last audit (`ctx.sessions.create().run()`
  doesn't exist on the installed DSH API) and are now fixed and verified --
  `node plugins/_selftest.mjs` passes 21/21 against the real files, not
  mocks. See `plugins/PLUGIN-FIXES.md` for the full API citation trail.

Every other plugin (dsh-observability, dsh-hunt-state, dsh-skill-admission,
dsh-h1-classifier, etc.) is background observability/skill-management
infrastructure and should not be invoked directly.

## Rules
1. Never run tools outside scope.txt.
2. You do not plan the hunt. JEV plans it. After init, the only legal
   control flow is: decide → run the executor in jev-decision.json →
   decide again. Do not skip decide. Do not pick a stage, skill, vuln, or
   test method yourself.
3. Wait for the current executor to finish before calling decide again.
4. Report progress using `hunt_mark` after every executed step.
5. Stop and report if any executor fails.
6. If `next_action` is `human_gate`, stop and show the user
   hunts/<domain>/jev-decision.json. Do not continue.

## The hunt loop

When the user says "hunt <domain>", do this. Do not run recon-01 through
recon-17 in a hardcoded order.

### 0. Init once

    bash scripts/pipeline/run.sh init <domain> "<scope host1
    host2
    host3>"

### 1. Let JEV drive

    bash scripts/pipeline/run.sh decide <domain>

Read only the JSON printed on stdout (and `executor` inside it). Do not
load recon summaries or skill checklists into your own context.

Optional: `bash scripts/pipeline/run.sh loop <domain>` runs decide plus
every `kind: bash` executor (recon phases and skill scoring) until JEV
needs you. Exit 10 means take the printed `executor` and do that LLM
step, then `decide` again. Exit 0 with `human_gate` means stop.

### 2. Run exactly one executor

`executor.kind` is the only thing you act on:

| kind | What you do |
|---|---|
| `bash` | Run `executor.command`. Nothing else. |
| `subagent` | Run `executor.command` if present, then spawn that subagent. Return a short confirmation, not the trace. |
| `plugin` | Call the named plugin on `executor.input`. Write `executor.write`. |
| `write` | Write SUMMARY.md. Stop. |
| `halt` | Stop. Show the user the decision file. |

Then `hunt_mark` the stage, then `decide` again unless kind was `halt`
or `write`.

JEV (TypeSafe System One, `https://api.typesafe.ai/v1/systemone`) does not
write text. `scripts/pipeline/jev-decide.mjs` asks it: what next, which
recon phase, which skill, which vuln, how to test. Hunt policy then
clamps illegal jumps (no recon → phase 01; test without keyword scores →
score_skills; chain without validated findings → earlier stage;
confidence < 0.45 or human_review > 0.7 → human_gate; critical/high
nuclei or any phase-15 hit → human_gate). Requires `TYPESAFE_API_KEY`
(`.env` in the repo root is read if unset). Optional `TYPESAFE_MODEL`
(default `jev-latest`).

`next_action` values: `deepen_recon`, `score_skills`, `select_and_test`,
`prefilter`, `falsify`, `prove`, `chain`, `report`, `quality`, `deliver`,
`human_gate`, `stop`. Test methods stay in the closed set
`checklist_walk`, `tool_hit_falsify`, `flow_step_skip`, `auth_swap`,
`param_mutation`, `version_match`, `hold`. JEV does not invent payloads.

Each decide appends one line to `hunts/<domain>/jev-log.jsonl`.

### How to execute each action (only when JEV names it)

Recon phases 01–17 still exist as scripts. Run the single phase in
`executor.command` / `recon_phase`. Dependencies are enforced in
jev-decide, not by you. Phases 12–17 are the proven-methodology ones
(response cache, secrets, nuclei, one-liners, GitHub dorks, interesting
endpoints). Do not batch "the rest of recon" because the old manual
said to.

**score_skills** — `bash scripts/pipeline/run.sh skills <domain>`. Keyword
overlap is evidence. JEV still picks the skill.

**select_and_test** — `bash scripts/pipeline/run.sh hypothesis <domain>`
then spawn a subagent on `hypothesis-prompt.txt`. It writes
`hypotheses.json`. Return count and top priorities only.

**prefilter** — `pre_validation_filter` per hypothesis → `hypotheses-pass.json`.

**falsify** — subagent on pass-list + raw recon for tool hits → keep
verdict==true AND confidence>=0.6 in `hypotheses-real.json`.

**prove** — `validate_finding` baseline+probe → `validated.json`. Treat
`confidence: "low-likely-noise"` as not validated.

**chain** — `build_chain` → write `chains.json` yourself.

**report** — `write_report` per finding → `reports/report-<id>.md`.

**quality** — subagent checklist → copy passers to `reports/approved/`.

**deliver / stop** — write `SUMMARY.md`.

The old Stage 1 concurrent batches, Stage 2-before-2.5 linear order, and
"run every recon phase first" are retired. JEV may still run them, one
legal phase at a time.

### select_and_test — hypothesis **[SUBAGENT]**

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

When JEV names these later actions, execute them as written. Do not run
them because they are "next in the old pipeline."

### prefilter **[TOOL]**

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

JEV is the planner. The LLM is the executor. JEV chooses the next
stage, the skill, the vulnerability, and the test method. DeepSeek
writes hypotheses, chains, and reports only inside that choice.
