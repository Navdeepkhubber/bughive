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
  `node plugins/_selftest.mjs` passes 32/32 against the real files, not
  mocks. See `plugins/PLUGIN-FIXES.md` for the full API citation trail.

### Correctness tools (added after the first audit)

These exist because the pipeline could previously reach `deliver` and print
"no findings" without ever knowing what it had not tested, and nothing checked a
report's claims against what the hunt actually did.

- `scope_check` / `scope_assert` (dsh-scope-guard) -- **[TOOL]**. Wildcard-aware
  scope matching (`*` = one label, `**` = many, `!` excludes, default deny). Call
  `scope_assert` BEFORE any request loop. `dsh-fp-filter`'s older check compared
  hosts with `===`/`endsWith`, so a wildcard-only scope (`g-*.0.threema.ch`)
  matched nothing and the guard silently did nothing.
- `coverage_init` / `coverage_mark` / `coverage_gaps` / `coverage_summary` /
  `coverage_gate` (dsh-coverage) -- **[TOOL]**. The vuln-class x asset matrix.
  Run `coverage_init` right after `init`. Mark each cell as you test it. `n/a`
  and `blocked` REQUIRE a reason, which is how the hunt states honestly what it
  did not test. **`coverage_gate` is enforced in `jev-decide` policy**: `deliver`
  and `stop` are clamped to `human_gate` while any critical cell is unresolved.
  An untested cell is not a clean bill of health.
- `hunt_journal_append` / `hunt_journal_tail` / `hunt_journal_leads` /
  `hunt_journal_stats` (dsh-hunt-journal) -- **[TOOL]**. Durable evidence memory
  across sessions. Log a `lead` for anything promising and a `deadend` for
  anything not worth retrying; `hunt_journal_leads` is the resume-work queue.
- `triage_gate` (dsh-triage-gate) -- **[TOOL]**. The 7-Question Gate, mechanised,
  plus the always-rejected keyword list and a conservative CVSS hint. Every
  question must be `true`; a missing answer counts as NO. Run it before writing
  any report.
- `analyze_js` (dsh-js-analyzer) -- **[TOOL]**. Static analysis of local JS/HTML
  bundles for client-side redirect allowlists, client-side authorization, DOM XSS
  sinks, postMessage handlers, hardcoded secrets, debug flags, internal hosts and
  more. Emits leads with a suggested next request. `recon-07` now calls the same
  engine via `plugins/dsh-js-analyzer/cli.mjs` (it was a stub before, so JS was
  collected and never read).
- `audit_report` (dsh-claim-audit) -- **[TOOL]**. Checks every endpoint claim in a
  report against the hunt's own evidence and flags assertions no request ever
  backed. **Run this before submitting any report or writing a "no findings"
  SUMMARY.** An unverified negative is worse than no report: an earlier report in
  this repo claimed SQLi testing across four endpoints when payloads had gone to
  one.
- `validate_xss_browser` / `browser_snapshot` (dsh-browser-validate) -- **[TOOL]**.
  Headless Chromium. `validate_xss_browser` confirms the payload ACTUALLY EXECUTED
  (dialog fired / `window.__bh_xss` set / console pattern); a reflected string is
  not an XSS. Fails LOUDLY when the browser is missing rather than reporting a
  quiet false negative. Chromium is installed via `npx playwright install chromium`.
- `dedup_assets` / `simhash_text` (dsh-asset-dedup) -- **[TOOL]**. Cluster
  near-identical responses (clone/staging hosts) by 64-bit SimHash over word
  shingles. Test the representative, not every clone, and treat a finding in one
  member as a lead for its siblings.
- `retrieve_skills` / `skill_rag_reload` (dsh-skill-rag) -- **[TOOL]**. TF-IDF
  retrieval over `skills/**`. Catches paraphrase that keyword overlap misses
  ("file parameter resolved on disk" -> LFI). Evidence only; JEV still chooses.
- `parse_program_scope` / `scope_txt` (dsh-scope-intake) -- **[TOOL]**. Turn a
  program's scope/policy prose into in-scope patterns, exclusions, policy flags and
  `excluded_classes`. Feed `excluded_classes` into `triage_gate` via
  `programExclusions` so a class the program forbids is killed before write-up.
- `eval_scenarios` / `eval_start_fixture` / `eval_stop_fixture` / `eval_score`
  (dsh-eval) -- **[TOOL]**. Measures the pipeline itself against a bundled
  vulnerable fixture (loopback-only) with ground truth: true positives, false
  positives, false negatives, precision/recall/F1 and a per-class breakdown. **Use
  it whenever you change the pipeline** -- an unmeasured change is a guess.
- `oob_start` / `oob_mint` / `oob_poll` / `oob_wait` / `oob_stop` (dsh-oob) --
  **[TOOL]**. Out-of-band interaction listener (HTTP + UDP DNS) for blind SSRF /
  XXE / XSS / JNDI. Also available to the bash pipeline via
  `plugins/dsh-oob/oob-cli.mjs` (used by recon-15).
- `validate_timing` / `validate_boolean` / `validate_redirect` / `validate_oob`
  (dsh-validators) -- **[TOOL]**. Per-class proof conditions. Prefer these over
  `validate_finding` whenever the bug class matches.

### Pipeline stages that expose the tools to bash

The plugin tools are reachable from the shell through `scripts/plugin-call.mjs`
(any plugin, any tool, JSON in/out). These `run.sh` stages wrap the ones a hunt
should actually invoke:

| Stage | What it does |
|---|---|
| `run.sh scope <domain> <file>` | Parse a program page into `scope.txt` plus `program-scope.json` (exclusions + policy flags + `excluded_classes`). |
| `run.sh coverage init\|gate\|gaps\|summary <domain>` | Coverage matrix; `gate` **exits non-zero** while critical cells are unresolved, so it can block delivery. |
| `run.sh ingest <domain>` | Harvest request evidence from `recon/` into the journal (proxy history). Idempotent. Run it after recon so `audit` has evidence. |
| `run.sh dedup <domain>` | Collapse clone/staging hosts from the response cache into `recon/asset-clusters.json`. |
| `run.sh retrieve <domain>` | TF-IDF skill retrieval as evidence; `skills` also merges RAG into selection. |
| `run.sh audit <domain> <report>` | Verify a report's claims against the hunt's evidence; **exits non-zero** on an unsupported claim. |
| `run.sh eval scenarios\|start\|stop\|score` | The self-measurement harness (see `dsh-eval`). |
| `run.sh proxy start\|stop\|requests\|env <domain>` | Live capture proxy. `start` records a pid; `env` prints the exports; then run any tool and its traffic lands in `recon/proxy-capture.jsonl`. Add `--mitm` for full HTTPS capture. |
| `run.sh shots <domain>` | Screenshot + perceptual-hash each in-scope host, then cluster clones into `recon/image-clusters.json`. |

**Capturing traffic you did not originate.** The journal only saw pipeline requests
until the proxy existed. To capture a raw `curl`, a python script or a third-party
binary:

```
bash scripts/pipeline/run.sh proxy start <domain>
eval "$(bash scripts/pipeline/run.sh proxy env <domain>)"
# ... run whatever you like ...
bash scripts/pipeline/run.sh proxy stop <domain>
bash scripts/pipeline/run.sh ingest <domain>     # folds captures into the journal
```

HTTPS is tunnelled and the CONNECT target recorded. With `--mitm` the proxy generates a
CA (openssl) and terminates TLS to capture full paths; clients must trust it
(`curl --cacert "$(node plugins/dsh-proxy/proxy-cli.mjs ca | jq -r .ca_cert)"`,
`NODE_EXTRA_CA_CERTS=...`). Neither mode is on by default because MITM requires
trusting a generated CA.

Typical order: `init` -> `scope` (if a program page exists) -> `proxy start` (if you
will run tools by hand) -> recon phases -> `ingest` -> `skills` -> `coverage init` ->
hunting -> `coverage gate` -> `shots`/`dedup` for clone collapsing -> `audit` before
any report.

**Skill retrieval** has three layers: TF-IDF always, a curated security concept
thesaurus for synonymy ("server fetches a URL" -> SSRF) which is offline and
deterministic, and an optional embeddings rerank when `EMBEDDINGS_URL` or
`OPENAI_API_KEY` is set. `retrieve_skills` reports which layer fired, so a result is
never mistaken for semantic matching when only lexical matching ran.

See `IMPROVEMENTS.md` for the research these came from, and for the prioritised
roadmap (Playwright/browser XSS validation, benchmark harness, asset dedup,
source-audit phase) -- all of which are now implemented; that file records the
status and the known gaps.

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
7. Run `coverage_init` immediately after `init`, and `coverage_mark` every cell
   you test. Never report a clean result while `coverage_gate` fails. Cells you
   did not test must be marked `n/a` or `blocked` WITH A REASON -- silent omission
   is how a hunt lies about its own coverage.
8. Run `audit_report` on every report and on SUMMARY.md before delivering. If it
   flags an unsupported claim, either produce the missing evidence or cut the
   claim. Never ship an assertion the hunt cannot back with a request.
9. Record leads and dead ends with `hunt_journal_append` as you go. The next
   session has no memory of this one; the journal is the only thing that survives.
10. After changing any plugin, prompt or skill, run `node plugins/_selftest.mjs`
   and then the eval harness (`eval_start_fixture` -> probe -> `eval_score`).
   An unmeasured change is a guess; report the before/after precision and recall.
11. If the target has source available (open-source app, SDK, vendor client),
   place a checkout at `hunts/<domain>/source/` and run
   `bash scripts/pipeline/run.sh recon-18 <domain>`. White-box consistently
   outperforms black-box on published benchmarks, and the phase reports
   `degraded: true` when no checkout exists rather than silently skipping.

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
