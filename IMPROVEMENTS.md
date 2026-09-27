# bughive — improvement roadmap, grounded in published AI-pentest results

Research date: 2026-09. Method: compared bughive's capabilities against the systems that
publish reproducible benchmark results, then implemented the gaps that were self-contained
and testable offline. No target was contacted during this work.

---

## 1. What the leaders actually do

**The XBOW validation benchmark** (104 web-app CTF challenges, black-box unless noted) is
the closest thing to a common yardstick. Current standings:

| System | Score | Mode |
|---|---|---|
| Shannon Lite (KeygraphHQ) | 96.15 % (100/104) | white-box, hint-removed |
| Strix (usestrix) | 96.15 % (100/104) | black-box |
| PentestGPT (USENIX '24) | 86.5 % | black-box |
| Red-MIRROR | 86.0 % | black-box, multi-agent + RAG |
| XBOW (commercial) | ≈85 % | black-box |
| Cyber-AutoAgent | 84.6 % (v0.1.3) vs 45.9 % (v0.1.0) | single-agent → **meta-agent** |
| MAPTA | 76.9 % | multi-agent |

Three findings matter more than the rankings:

**a) Precision, not detection, is the bottleneck.** XBOW reported ~1,060 submissions with
208 duplicates, 209 informative and 36 N/A — roughly 40 % noise, even for the best system.
Their fix was explicit: *"we developed the concept of validators, automated peer reviewers
that confirm each vulnerability"*, and for XSS they *"use a headless browser to visit the
target site to verify that the JavaScript payload was truly executed"*. Detection is cheap;
proof is the product.

**b) Blind classes are where agents collapse.** MAPTA's per-class breakdown is
SSRF 100 % · Misconfig 100 % · SSTI 85 % · SQLi 83 % · Authz 83 % · Cmd-Inj 75 % ·
XSS 57 % · **Blind SQLi 0 %**. Anything that only proves itself out of band is the weakest
area across the field.

**c) Architecture that scores.** Strix: a root agent with per-specialism sub-agents
(`skills="authentication_jwt,business_logic"`), fresh context per child
(`inherit_messages=False`), shared sandbox and shared **proxy history**, 300 iterations per
agent. Cyber-AutoAgent's jump from 45.9 % → 84.6 % came purely from restructuring a single
agent into a meta-agent. Red-MIRROR adds RAG. Scope/asset triage is automated because
program policies are not machine-readable — XBOW notes it was *"officially removed from a
program that didn't allow automatic scanners"*, so policy compliance is itself a feature.

Sources: [XBOW validation benchmark](https://github.com/xbow-engineering/validation-benchmarks) ·
[cross-project comparison](https://github.com/PurpleAILAB/Decepticon/blob/main/docs/benchmark-comparison.md) ·
[XBOW: The Road to Top 1](https://xbow.com/blog/top-1-how-xbow-did-it) ·
[Strix agent architecture](https://docs.strix.ai/index) ·
[Strix agents](https://mintlify.wiki/usestrix/strix/concepts/agents).

---

## 2. Gap analysis against bughive

| Capability | Leaders | bughive (before) |
|---|---|---|
| Per-class proof conditions | XBOW "validators" | one generic HTTP diff (`validate_finding`) |
| Browser confirmation of XSS | headless browser checks execution | **Playwright declared as a dependency but not installed**; `recon-11` silently degrades to katana |
| Out-of-band confirmation | callback infrastructure | `recon-15` needed a hand-set `BUGHIVE_COLLABORATOR_URL`; **no listener, no polling, no correlation** |
| Blind variants | weak everywhere (0–57 %) | impossible to confirm at all |
| Asset dedup (clones/staging) | SimHash + screenshot imagehash | none |
| Scope/policy ingestion | LLM-parsed, policy-aware | manual `scope.txt` string |
| Measuring itself | own benchmark + CTFs | **no eval harness** |

The Playwright point is worth emphasising: `package.json` lists `playwright` and the
postinstall message says to install chromium, but it is not installed, so the flow-mapping
phase reports `tools_skipped` and the multi-step-flow hypothesis source is quietly empty.

---

## 3. Implemented in this pass

All verified by `node plugins/_selftest.mjs` → **34/34 passing**, plus
`node scripts/pipeline/jev-decide.mjs --selftest` → 12/12.

**`dsh-oob`** — out-of-band interaction listener (HTTP + UDP DNS). `oob_start`,
`oob_mint`, `oob_poll`, `oob_wait`, `oob_stop`. Mints per-payload tokens, records every
inbound interaction, correlates it back to the token, and waits for confirmation. This is
the difference between "we sent a payload and saw nothing" and "the target's server
resolved our token" — i.e. it makes blind SSRF/XXE/XSS/JNDI *provable* rather than
undetectable. Binds to loopback by default; `publicHost` opts into external reachability.

**`dsh-validators`** — the XBOW "validators" concept, per class:
- `validate_timing` — median-of-N baseline vs probe, requires the injected delay; rejects jitter.
- `validate_boolean` — TRUE must match baseline **and** FALSE must differ; rejects the "page differs every time" false positive.
- `validate_redirect` — server-side 3xx to an off-origin host only; a client-side JS redirect or a same-host bounce is not validated.
- `validate_oob` — confirms from an OOB interaction record.

**Planner wiring** — `coverage_gate` is enforced in `jev-decide`: `deliver`/`stop` clamp to
`human_gate` while critical coverage cells are unresolved (from the previous pass).

---

## 4. Prioritised roadmap

### P0 — closes the largest detection gaps

1. **Install Playwright + chromium, and make `recon-11` fail loudly when absent.**
   Currently the phase degrades silently, so a whole hypothesis source is empty and nothing
   says so. Then add `validate_xss_browser`: load the page, plant a unique token in the
   payload, and confirm execution (e.g. the token appearing in a `fetch`/`console` sink),
   which is exactly XBOW's XSS validator. This is the single cheapest precision win.
2. **Wire `dsh-oob` into the recon/triage path.** Point `recon-15` at the local listener
   instead of requiring an out-of-band collaborator, and record the interaction in the
   journal so `validate_oob` can consume it. Blind classes are currently the field's weak
   spot; making them confirmable is differentiation.
3. **Two-account requirement.** The Top-1 % checklist already says "2 test accounts
   (attacker + victim)" and it was never met on the Threema hunt — which is precisely why
   the highest-payout class (cross-tenant IDOR) was untestable. Make `coverage_mark` refuse
   to mark an IDOR/authz cell `tested` without two identities recorded, or mark it
   `blocked: no second identity` automatically.

### P1 — raises signal quality

4. **Benchmark harness.** `/eval` that runs a hunt against a fixed set of local vulnerable
   apps (OWASP Juice Shop, crAPI, VAmPI, DVWA) and reports true positives, false positives
   and false negatives per class. Without this, every change above is a guess; XBOW's own
   account attributes their progress to benchmarking first. Docker-based; keep it fully
   offline.
5. **Asset dedup.** SimHash over response bodies + screenshot imagehash to collapse
   `stage0001-dev…` clones. XBOW uses it to *"focus our efforts on unique, high-impact
   targets"*, and it doubles as cluster-hunting input: one bug in a clone family implies
   the siblings.
6. **Source-audit phase for white-box targets.** XBOW's zero-day work gave the model source
   code. The Threema engagement had complete client source available and used it only for
   protocol facts. A phase that runs Semgrep/CodeQL and then has an LLM triage the hits
   (rather than reporting them raw) would have been directly applicable.
7. **RAG over the skill library.** Red-MIRROR's gain comes from retrieval over techniques.
   `skill-select.sh` is keyword overlap only.

### P2 — autonomy and hygiene

8. **LLM scope/policy ingestion.** Parse the program page into scope + exclusions + rules
   ("no automated scanners", "no cache poisoning") and feed the exclusions to `triage_gate`
   so the tool never submits a class the program refuses. XBOW was removed from a program
   for exactly this.
9. **Per-agent iteration budgets and time-boxing.** Strix uses 300 iterations/agent; the
   methodology says max 45 min per parameter. Make the budget explicit so a hunt cannot
   wander or stop early by accident.
10. **Multi-skill sub-agent briefs.** JEV currently picks one skill per `select_and_test`.
    Strix loads several related skills per specialist sub-agent.
11. **Shared proxy history.** Strix agents share proxy history as common context; the
    journal is a partial substitute but does not capture every request automatically.

---

## 5. Honest limits of this work

- The new plugins are **written, tested and registered but not installed**; run
  `bash scripts/install.sh` and restart DSH.
- The OOB listener only proves *a* callback occurred. It cannot attribute an interaction to
  one of several simultaneous payloads unless tokens are minted per payload — which is why
  `oob_wait` documents that it returns on the first match.
- `validate_timing` is sound only against a stable endpoint; a target with variable latency
  needs more samples and a higher tolerance.
- `validate_boolean` compares *rendered* bodies; heavily dynamic pages will defeat it, which
  is the intended failure direction (it refuses to validate rather than guessing).
- Nothing here replaces a human decision about whether a finding is in scope. The
  `triage_gate` and `claim_audit` tools exist to make the reasoning auditable, not automatic.

---

## 6. Implementation status (all of P0/P1/P2)

Measured with `node plugins/_selftest.mjs` → **40/40 passing** and
`node scripts/pipeline/jev-decide.mjs --selftest` → 12/12. **26 plugins installed and
registered.**

### P0 — largest detection gaps

| # | Item | Status |
|---|---|---|
| 1 | Playwright installed + `validate_xss_browser` | **Done.** Chromium installed; the browser validator confirms real JS execution and refuses to confirm a merely-reflected payload. Verified end-to-end against the fixture. |
| 1b | `recon-11` fails loudly instead of degrading | **Done.** Three explicit states (ready / degraded / blocked), each writing `degraded: true` and a stderr warning with the exact remediation. It previously wrote a quiet note and exited 0. |
| 2 | Wire OOB into the recon path | **Done.** `plugins/dsh-oob/oob-cli.mjs` (`serve`/`poll`/`tokens`); `recon-15` now starts the local listener automatically instead of skipping blind classes when no collaborator is set. |
| 3 | Two-account enforcement | **Done.** `coverage_mark` refuses to mark IDOR / ATO / business-logic / OAuth as `tested` with fewer than 2 identities, and tells you to mark it `blocked` with a reason instead. |

### P1 — signal quality

| # | Item | Status |
|---|---|---|
| 4 | Benchmark harness | **Done.** `dsh-eval` + a loopback-only vulnerable fixture with 8 planted bugs across 8 classes and a ground-truth manifest. `eval_score` returns TP/FP/FN, precision/recall/F1 and a per-class breakdown. Demonstrated: precision 0.75 / recall 0.375 on a deliberately partial run. |
| 5 | Asset dedup | **Done.** `dsh-asset-dedup`: 64-bit SimHash over word shingles, Hamming clustering. Screenshot perceptual hashing deliberately **not** attempted (needs an image decoder; faking it would fail silently). |
| 6 | Source-audit phase | **Done.** `recon-18-source-audit`: consumes a checkout at `hunts/<domain>/source/`, runs Semgrep when present, else a built-in multi-language pattern pass (JS rule engine + Python/PHP/Java/Go/Ruby/Rust tables). Reports `degraded: true` when there is no checkout. Registered in `run.sh` and the JEV phase graph. |
| 7 | RAG over skills | **Done.** `dsh-skill-rag`: dependency-free TF-IDF ranking that handles paraphrase. Deliberately local (no embeddings API) so it works offline and in CI. |

### P2 — autonomy and hygiene

| # | Item | Status |
|---|---|---|
| 8 | Scope/policy ingestion | **Done.** `dsh-scope-intake` parses scope prose into in/out-of-scope patterns, policy flags and `excluded_classes`; `triage_gate` now takes `programExclusions` and kills a forbidden class outright. Sentence-based and order-agnostic ("no DoS" *and* "DoS is prohibited"). |
| 9 | Iteration budgets / time-boxing | **Done.** `MAX_DECIDES = 80` hard cap clamps to `human_gate`; `STALL_DECIDES = 20` flags a hunt that has burned 20 rounds with zero validated findings. Both surfaced in planner state. |
| 10 | Multi-skill sub-agent briefs | **Already satisfied.** `decision.skills` is an array, `writeDecision` persists it to `skills-selected.json`, and `hypothesis.sh` loads every selected skill into the brief. Verified, not re-implemented. |
| 11 | Shared proxy history | **Partially done.** `dsh-hunt-journal` is the durable cross-session evidence log and recon phases write request/response evidence to disk. A true live proxy capture (every request auto-recorded) is still missing. |

### Known gaps after this pass

- **P2.11** remains partial (see above).
- The OOB listener proves *a* callback occurred; attribution across simultaneous payloads
  requires one token per payload, which `oob_wait` documents.
- The eval fixture covers 8 classes; it is a smoke benchmark, not the 104-challenge XBOW
  suite. Its value is regression detection on *this* tool, not comparability with others.
- `recon-18` is only as good as the checkout supplied; nothing clones source automatically.
- The DSH profile's `pnpm-workspace.yaml` needed its `allowBuilds` placeholders replaced
  with real booleans before any plugin would install (`ERR_PNPM_IGNORED_BUILDS`).
  `scripts/install.sh` now repairs that automatically and continues past an individual
  plugin failure instead of aborting the whole run.

---

## 7. Integration pass — the gap that mattered most

A capability nothing calls is not a capability. After the P0/P1/P2 work, an audit of the
bash pipeline showed the new tools were reachable **only by the agent**:

```
analyze_js          referenced in 0 scripts      retrieve_skills      0
dedup_assets        0                            eval_score           0
parse_program_scope 0                            coverage_gate        0
audit_report        0                            coverage_init        0 (advice only)
```

So the final pass wired them in:

- **`scripts/plugin-call.mjs`** — a generic bridge (`plugin-call.mjs <plugin> <tool> <json>`)
  that loads any plugin, wires a minimal `tools` context, invokes one tool, and returns its
  JSON on stdout with plugin noise on stderr. Non-zero exit on failure so `set -e` works.
  This is what makes every deterministic tool available to bash.
- **`scripts/pipeline/_tools.sh`** — stages built on the bridge: `scope`, `coverage`,
  `dedup`, `ingest`, `audit`, `eval`, `retrieve`. `coverage gate` and `audit` exit non-zero
  on failure so they can actually block delivery.
- **`skill-select.sh`** — now merges TF-IDF retrieval with keyword overlap. Either signal
  can qualify a skill, so paraphrase recall improves; each selected skill records which
  signal fired.
- **Prove stage** — `validate_by_class` is now the primary prover, with `validate_finding`
  as fallback. The router maps each class to its real proof condition and refuses to
  pretend IDOR/CSRF/ATO/takeover are payload-provable.
- **`hunt_journal_ingest`** — harvests request evidence from `recon/` into the journal,
  idempotently. This closes **P2.11**: request history is now complete for
  pipeline-generated traffic, which is what `audit_report` and coverage read.
- **`recon-18` auto-clone** — clones from `hunts/<domain>/source-url.txt` or
  `BUGHIVE_SOURCE_REPO` so white-box audit is one step, not a manual prerequisite.

### Bugs this pass caught

Wiring things together found three defects that unit tests had missed:

1. **Excluded hosts became coverage assets.** `!blog.example.test` from `scope.txt` was
   loaded as a target, so the gate demanded testing hosts the program forbids. Fixed in
   `discoverAssets`.
2. **The `scope` stage reported wrong fields.** It read counts out of the `scope_txt`
   payload instead of the full parse, so `out_of_scope` and `policy_flags` always looked
   empty even when exclusions were found.
3. **`cmd_coverage gate` exit code was never verified** — it was masked by a pipe in my
   own test harness. Confirmed separately that it returns 1.

### Remaining gaps after everything

- **P2.11 is now complete for pipeline traffic**, but there is still no live HTTP proxy
  capturing agent-issued requests that bypass the pipeline (e.g. a raw `curl` in a bash
  step). The journal is complete only for what recon writes or the agent logs.
- The eval fixture covers 8 classes and is a regression benchmark, not comparable to the
  104-challenge XBOW suite.
- `dedup_assets` has no screenshot/perceptual-image half (deliberate: it would need an
  image decoder and faking it would fail silently).
- Skill retrieval is TF-IDF, not embeddings. It handles paraphrase but not synonymy
  ("SSRF" vs "server fetches a URL"), which a hosted embedding model would. Kept local so
  it works offline and in CI.

---

## 8. Closing the four remaining gaps

**27 plugins. `node plugins/_selftest.mjs` → 43/43 passing.**

### 8.1 Live capture proxy (was: journal only covered pipeline traffic)

`dsh-proxy` is a real HTTP/HTTPS forward proxy, plus `proxy-cli.mjs` and a `run.sh proxy`
stage. It closes the hole where a raw `curl` in a bash step was invisible.

Three modes, all verified end-to-end against loopback servers:

| Mode | Capture |
|---|---|
| plain HTTP | full method, absolute URL, headers, body |
| HTTPS (default) | CONNECT target host:port — proves which hosts were contacted |
| HTTPS `--mitm` | full inner request; CA generated with openssl, per-host leaf certs minted on demand and cached |

MITM is opt-in because it requires the client to trust a generated CA. `run.sh ingest`
now folds the capture file into the journal, so `audit_report` and coverage see traffic
the agent generated outside the pipeline.

### 8.2 Real synonymy in skill retrieval

`dsh-skill-rag` now runs three layers:

1. **TF-IDF** — always available, no dependencies, no network.
2. **Concept thesaurus** (20 security concepts) — offline and deterministic. This fixes
   the exact failure reported: "server fetches a URL" contains none of the letters
   "ssrf". Verified: that phrase now retrieves `seeds/ssrf`.
3. **Optional embeddings** — any OpenAI-compatible `/embeddings` endpoint via
   `EMBEDDINGS_URL` or `OPENAI_API_KEY`, disk-cached, blended with the lexical score.
   `retrieve_skills` reports `embeddings: "used" | "not-configured" | "unavailable"`, so a
   lexical-only result is never mistaken for semantic matching.

Layers 1–2 always run, so retrieval never depends on the network and CI keeps working.

### 8.3 Perceptual image hashing (was: deliberately skipped)

The honest reason it was skipped was that a perceptual hash needs an image decoder. The
browser **is** one — so `screenshot_hash`, `hash_screenshots` (batch, one browser) and
`hash_images` decode via canvas and return dHash/aHash. `dedup_by_hash` clusters on
Hamming distance, and `run.sh shots` screenshots + clusters in one step.

Verified: two visually identical pages land in one cluster (distance 3/256) and an
unrelated page stands alone (distance 11/256).

**Two bugs this surfaced**, both of which would have silently produced useless output:
- `popcount64` masked to 64 bits, so a 256-bit hash was truncated before comparison and
  **every distance came back 0**. Added a width-agnostic `popcount`.
- The first version hashed the viewport, which is mostly whitespace, so unrelated pages
  collided at 5/64. Now captures `fullPage` and the threshold is ~3% of bits.

### 8.4 Eval fixture: 8 → 19 bugs, 19 classes, 3 tiers

Expanded with tiers (`L1` single request, `L2` second request/identity, `L3`
chaining/concurrency) and, importantly, **benign endpoints that exist purely to make
false positives measurable** (`/api/version` is a banner-only trap; flagging it is wrong).

New classes: idor-write, mass-assignment, ssti, jwt (alg=none), nosql, cors,
host-header-injection, graphql, race-condition, xxe, cache-poisoning.

Every planted bug is verified by a behaviour test — 19/19. That test caught a genuine
fixture defect: the NoSQL endpoint read `get("q")`, but an operator payload arrives as
the parameter name `q[$ne]`, so the bug was **untriggerable as written**. It now emulates
an extended query parser.

Safety limits, stated rather than glossed: SSRF refuses non-loopback targets, and XXE
file reads are confined to `plugins/dsh-eval/fixture-data/` (reading `/etc/passwd` is
refused and reported as a blocked attempt).

Still not comparable to the 104-challenge XBOW suite — but it is now a real per-class,
per-tier regression benchmark that runs offline with no Docker.
