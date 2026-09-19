# Plugin fixes — porting the bounty pipeline to the installed DSH API

Scope: `plugins/` only. No file outside `plugins/` was modified. No DSH server/GUI was
restarted, killed, or reconfigured. No request was made to `bdo.ch` or any other
bug-bounty target; the only network activity in the self-test is `127.0.0.1` loopback.

Reference checkout (authoritative): `/opt/homebrew/lib/node_modules/@deepseek-ai/dsh/`.
All `file:line` citations below are relative to that directory unless stated otherwise.

Run the offline proof:

```bash
node plugins/_selftest.mjs      # 21/21 passed
node --check plugins/<file>.js  # each touched file
```

---

## Executive summary

| Plugin | Tool | Status | Root cause |
|---|---|---|---|
| `dsh-recon-orchestrator` | `run_recon_phase` | **FIXED** | `sessions.create().run()` does not exist |
| `dsh-finding-validator` | `validate_finding` | **FIXED** | `ctx.tools.call("http_request", …)` — no such method, no such tool |
| `dsh-chain-builder` | `build_chain` | **FIXED** | `sessions.create().run()` does not exist |
| `dsh-report-writer` | `write_report` | **FIXED** | `sessions.create().run()` does not exist |
| `dsh-skill-loader` | `load_skills_for_target` | **UNTOUCHED** (regression-tested) | — |

"Fixed" here means: ported to APIs that exist in the installed checkout and proven by an
offline harness. It does **not** mean the tools have been executed inside the running
server — see [What remains unverified](#what-remains-unverified).

---

## 1. The API facts the port relies on

### 1.1 `ctx.sessions.create()` is synchronous and has no `run()`

- `@deepseek-ai/dsh-session/lib/types/index.d.ts:342`
  `create(id?: SessionId, options?: CreateSessionOptions): Session`
- `:317` `SessionStore extends Service`; `:103` `class Session`.
  Reading `:103-293` confirms the members are `eventAt`, `snapshotEvents`, `ownEvents`,
  `append`, `deriveEventMessage`, `flush`, `fork`, `get`, `list`, … — **no `run`**.
- The observed error text `session header id "[object Object]" does not match session id
  "[object Object]"` is exactly what happens when the options object is passed as the
  `id` positional argument, as the old code did
  (`await ctx.sessions.create({ title: … })`).

### 1.2 The correct way to spawn a child agent and await its text: `ctx.subagents.start()`

- `@deepseek-ai/dsh-subagent/lib/types/index.d.ts:296`
  `start(name: string, request: SubagentStartRequest): Promise<SubagentRun>`
- `@deepseek-ai/dsh-subagent/lib/types/types.d.ts:136-154` — `SubagentStartRequest`:
  `{ label?, prompt: ContentBlock[], parent: Agent, signal: AbortSignal, agentOptions?, … }`
- `:292-318` — `SubagentRun { id, localAgent, result: Promise<SubagentResult>, dispose(): Promise<void> }`
- `:256-282` — `SubagentResult { output: ContentBlock[], structured?, diagnostic?, stopReason }`
  where `stopReason` is `'completed' | 'aborted' | 'error' | 'max-tokens' | 'refusal'`.
- The caller's `Agent` comes from the tool body's second argument:
  `@deepseek-ai/dsh-tools/lib/types/index.d.ts:284` `ToolRunContext extends ToolExecution`;
  `:207` `readonly agent?: Agent`.
- Canonical, shipping example — the implementation behind the harness `subagent` tool:
  `@deepseek-ai/dsh-tool-subagent/lib/index.js:490-561`. It reads
  `const parent = exec.agent`, calls `ctx.subagents.start(config.provider, { label,
  prompt: [{ type: 'text', text }], parent, signal: exec.signal })`, then collects
  `run.result` and **always** calls `run.dispose()` (`:314-331`, `settleForegroundRun`).
- Provider identity: `@deepseek-ai/dsh-base/cordis.patch.yml:331-334` registers
  `@deepseek-ai/dsh-subagent-spawn-in-process` with `providerName: spawn`; `:328-339`
  also registers `fork`. `spawn` is therefore the deployment default.
- Partial `agentOptions` is legal: the spawn driver calls
  `resolveChildAgentOptions(parent, request.agentOptions, childDepth)` at
  `@deepseek-ai/dsh-subagent-in-process-driver/lib/index.js:186`, which merges the request
  over inherited parent values (documented at
  `@deepseek-ai/dsh-subagent/lib/types/child-agent.d.ts:44-52`).

### 1.3 `ctx.tools.call` does not exist; the registry exposes `execute`

- `@deepseek-ai/dsh-tools/lib/index.js` — `ToolRuntime` public methods are
  `register` (`:2773`), `restrict` (`:2790`), `guard` (`:2816`), `view` (`:2854`),
  `get` (`:2890`), `schemas` (`:2918`), `executionMode` (`:2951`), `execute` (`:730`).
  There is **no `call`**.
- Replacement contract: `@deepseek-ai/dsh-tools/lib/types/index.d.ts:730`
  `execute(exec: ToolExecutionInput): Promise<ToolExecutionResult>` with
  `ToolExecutionInput { callId, name, arguments, agent?, parent?, signal }` (`:197-221`)
  and the result union at `:390-412` (success `value`/`content`, failure `error`).
- The validator does **not** use this path, because the tool it wanted
  (`http_request`) is not registered anywhere. Verified: the only occurrences of
  `http_request` in the repo are the two broken lines themselves
  (`plugins/dsh-finding-validator/index.js:25-26` before the fix).

### 1.4 A sanctioned HTTP capability exists: `ctx.web.fetch`

- `@deepseek-ai/dsh-web/lib/types/index.d.ts:42-89` — `WebRuntime` (registered as
  `ctx.web`), method
  `fetch(request: WebFetchRequest, signal?: AbortSignal): Promise<WebFetchResult>` (`:89`).
- `@deepseek-ai/dsh-web/lib/types/types.d.ts:71-92` — request `{ url }`; result
  `{ url, statusCode, body: { kind: 'html'|'text', content }, truncated }`.
  **A non-2xx response is a result, not a throw**; failures throw `WebError` with a
  `.code` (`:114-129`).
- Composed in the base host: `@deepseek-ai/dsh-base/cordis.patch.yml:436-440`
  (`@deepseek-ai/dsh-web`, `fetchProvider: http`) and `:447-448`
  (`@deepseek-ai/dsh-web-fetch-http`).
- Provider limits/policy: GET-only (the provider request type at
  `@deepseek-ai/dsh-web-fetch-http/lib/types/provider.d.ts` has no method/headers/body),
  public-IP pinned, same-origin redirects only, defaults `timeoutMs: 30000`,
  `maxRedirects: 5` (`@deepseek-ai/dsh-web-fetch-http/lib/index.js:647-648`), URL policy at
  `:264-293`, redirect/read handling at `:447-479`.
- **Limitation that drove the design:** the seam cannot send custom headers, a request
  body, or a non-GET method, so it cannot replay authenticated findings.

### 1.5 `ctx.emit` / `ctx.get`

- `@deepseek-ai/cordis/lib/types/events.d.ts:142` — `emit(...args: any[]): void`.
- `@deepseek-ai/cordis/lib/types/reflect.d.ts:14-16` — `get(name, strict?): … | undefined`.
  Used opportunistically for the optional `web` service, the documented pattern
  (`@deepseek-ai/dsh-tools/lib/types/index.d.ts:783`).

---

## 2. Per-plugin changes

### 2.1 `dsh-recon-orchestrator`

**Old**

```js
export const inject = ["tools", "sessions"];
…
const s = await ctx.sessions.create({ title: `recon ${args.phase} ${args.domain}` });
const r = await s.run(prompt, { maxTokens: 30000 });
return r.output || "";
```

**New**

```js
export const inject = ["tools", "subagents"];
…
async execute(args, exec) {
  return runChild(ctx, cfg, `recon ${args.phase} ${args.domain}`, prompt, exec);
}
```

`runChild` resolves `ctx.get("subagents")`, requires `exec.agent`, checks the configured
provider is registered, then:

```js
const run = await ctx.subagents.start(cfg.provider, {
  label,
  prompt: [{ type: "text", text: prompt }],
  parent,
  signal: exec.signal,
  agentOptions: { maxTokens: cfg.maxTokens },
});
// await run.result, always run.dispose(), then join text blocks
```

**API evidence:** §1.2 (all citations). **Preserved:** tool name `run_recon_phase`,
description, `parameters` JSON schema, `required: ["phase","domain"]`,
`output.schema = { type: "string" }`, `render` projection, prompt text, `maxTokens: 30000`
(now via `agentOptions`), `phasesDir`/`outputDir` config, `console.log` banner.

**Changed behaviour (intentional):** the child is a fresh `spawn` subagent (its own
session + system prompt, zero inherited conversation), not a bare titled session. This is
the closest sanctioned equivalent and is arguably better for recon (fresh context). Config
gains `provider` (default `"spawn"`).

**`inject` change:** `"sessions"` → `"subagents"`, because the code no longer touches
`ctx.sessions` and needs the subagent registry. Exported module shape is unchanged.

### 2.2 `dsh-chain-builder`

Same port as 2.1, with the existing playbook read preserved verbatim
(`readdir`/`readFile` over `cfg.playbooksDir`, joined bodies into the prompt).

**Old:** `const s = await ctx.sessions.create({ title: "chain-build" }); const r = await s.run(…)`
**New:** `return runChild(ctx, cfg, "chain-build", prompt, exec)` → `ctx.subagents.start`.
**Preserved:** `build_chain` schema, `findings` JSON parsing, `maxTokens: 20000`, prompt
text, `playbooksDir` config, tool output contract.
**Unchanged throw path:** malformed `findings` JSON still throws `SyntaxError` (the
registry materializes it as an `isError` tool result) — the pre-existing behaviour.

### 2.3 `dsh-report-writer`

Same port. **Old:** `ctx.sessions.create({ title: … }).run(prompt, { maxTokens: 60000 })`.
**New:** `runChild(ctx, cfg, \`report ${finding.id || "?"}\`, prompt, exec)`.
**Preserved:** `write_report` schema, `finding`/optional `chain` parsing, prompt text,
`maxTokens: 60000`, `template: "hackerone"` config key, output contract.

### 2.4 `dsh-finding-validator`

**Old**

```js
const b = await ctx.tools.call("http_request", baseline);
const p = await ctx.tools.call("http_request", probe);
```

**New** — a structured, non-throwing transport layer:

1. `JSON.parse` of `baseline`/`probe`, each wrapped; failure returns
   `{validated:false, diff:…, error:{code:"BASELINE_JSON_PARSE"|"PROBE_JSON_PARSE", …}}`.
2. `normalizeRequest` accepts a URL string, or
   `{ url|target|endpoint, method?, headers?, body?, timeoutMs? }`; bad shape returns
   `error.code = "INVALID_REQUEST"`.
3. Transport selection:
   - **plain GET** (no method≠GET, no headers, no body) **and `ctx.web` available** →
     `ctx.web.fetch({url}, signal)` — the sanctioned, GET-only, public-IP-pinned seam.
   - otherwise → `curl` via `node:child_process.execFile` (see below).
4. Diff semantics **unchanged**:
   ```js
   statusChanged = b.status !== p.status
   lengthDelta   = Math.abs(len(b.body) - len(p.body))
   bodyDiffers   = b.body !== p.body
   validated     = statusChanged || bodyDiffers
   ```
5. On either transport error: `{ validated:false, diff:{…zeros…}, error, statuses,
   transports }` — **no throw**. `ctx.emit("finding/validation", …)` still fires (success
   payload keeps `{baseline, probe, diff, validated}` and adds `statuses`/`transports`).

**curl fallback** (`node:child_process.execFile`, no new npm dependency):

- `-sS --max-time <ceil(timeoutMs/1000)> [-X <METHOD> | --head] -o - -w '\n__DSH_HTTP_STATUS__%{http_code}'`
- **GET by default**; a non-GET method is used only when the caller explicitly supplies
  `method`. Headers/body are passed through only when the caller supplied them. `HEAD` uses
  curl's `--head` (`-X HEAD` makes curl wait for a response body that never arrives).
- Hard timeout: curl `--max-time` **and** `execFile` `timeout: timeoutMs + 2000`.
- stdout-only capture (`-o -`), no temp files — safe under a workspace-write file sandbox.
- The promise resolves (never rejects) with a structured result; spawn failure is caught
  and becomes `error.code = "CURL_SPAWN_FAILED"`, timeout `"CURL_TIMEOUT"`, non-zero exit
  `"CURL_EXIT_<code>"`.

**API evidence:** §1.3, §1.4, §1.5. **Preserved:** tool name `validate_finding`, schema
(`baseline`, `probe` JSON strings), output `{ type: "string" }`, `render`, the emitted
`finding/validation` event, `{validated, diff}` core return shape, and the
`maxAttempts`/`requireResponseDiff` config keys (retained; the diff rule is the original
one and does not consult them). **`inject` unchanged** (`["tools"]`) — `web` is consumed
opportunistically, so the plugin still loads in a deployment without it.

### 2.5 `dsh-skill-loader`

Not modified. A regression test asserts it still registers `load_skills_for_target` and
returns the master skill plus ≤3 ranked candidates.

---

## 3. Offline verification

`node plugins/_selftest.mjs` — **21/21 passed**, exit 0. It imports the real plugin
modules (not copies) and drives them through a mock `ctx` that implements only the
services/methods each plugin uses.

| # | Test | What it proves |
|---|---|---|
| 1 | all five modules import and export `{name, inject, apply}` | no syntax/ESM breakage |
| 2 | `run_recon_phase` start → text | provider `spawn`, `parent === exec.agent`, real `AbortSignal`, `maxTokens 30000`, prompt contains phase/domain/phases path, run disposed |
| 3 | non-`completed` stop reason | structured error + `dispose()` still called |
| 4 | `exec.agent` undefined | explicit rejection |
| 5 | `ctx.subagents` absent | explicit rejection |
| 6 | provider not registered | rejection lists available providers |
| 7 | `build_chain` happy path | playbooks read from disk and embedded, `maxTokens 20000` |
| 8 | `build_chain` malformed JSON | `SyntaxError` (preserved behaviour) |
| 9 | `write_report` with chain | label `report F-7`, `maxTokens 60000`, chain in prompt |
| 10 | `write_report` no chain / bad JSON | `Chain: null`; `SyntaxError` |
| 11 | `write_report` no subagents | explicit rejection |
| 12 | validator GET via `ctx.web` | `{statusChanged, lengthDelta:1, bodyDiffers}`, validated `true`, event transports `web` |
| 13 | validator identical responses | `validated false`, no throw |
| 14 | `ctx.web` rejects URL | `error.code = WEB_BLOCKED_URL`, validated false, event emitted |
| 15 | JSON-parse + bad-shape paths | `BASELINE_JSON_PARSE`, `PROBE_JSON_PARSE`, `INVALID_REQUEST`, no throw |
| 16 | `ctx.web` returns no numeric `statusCode` | `WEB_BAD_RESPONSE`, validated false — no invented diff |
| 17 | curl unreachable host | `CURL_EXIT_*`, validated false (loopback `127.0.0.1:1`, no external traffic) |
| 18 | curl POST + headers vs curl GET | `201` vs `200`, delta 9, both transports `curl` (loopback `node:http` server) |
| 19 | explicit `HEAD` through curl | `200`/`200`, returns promptly (uses `--head`, not `-X HEAD`) |
| 20 | headers present while `ctx.web` available | web seam skipped, curl used |
| 21 | skill-loader regression | master skill + ≤3 candidates |

`node --check` was run on all four fixed plugins and on `_selftest.mjs`: all OK.

The self-test's only network I/O is the loopback server above; no external host is
contacted, and `bdo.ch` is never resolved or requested.

---

## 4. What remains unverified

Honest list — none of the following is claimed as working:

1. **The edits have not executed inside the running host.** The offline harness proves the
   control flow against mocks; the real `SubagentRuntime`, `WebRuntime`, agent loop, and
   sandbox were not exercised. The tools have not been called through the live harness.
2. **Module reload is not guaranteed.** `~/.dsh/profiles/web/package.json` sets
   `patchReload: "live"`, and `@deepseek-ai/dsh/lib/profile-boot-Dk-7KqJc.js:321-338`
   auto-loads `@deepseek-ai/cordis-plugin-hmr` with `config: { root: [] }` and watches the
   profile/home patch files. Whether editing `plugins/*/index.js` source is picked up
   without a host restart was **not** verified; the `hmr` row in
   `@deepseek-ai/dsh-base/cordis.patch.yml:21-23` is `disabled: true`. Assume a `dsh` host
   restart may be required for the fixes to take effect.
3. **`inject` semantics.** The three agent-backed plugins now declare
   `inject = ["tools", "subagents"]` (was `["tools", "sessions"]`). If a deployment
   composes no `subagents` service, those plugins would not load at all. `dsh-base`
   composes it unconditionally (`@deepseek-ai/dsh-base/cordis.patch.yml:328-339`), and the
   `web` profile lists `@deepseek-ai/dsh-base` first
   (`~/.dsh/profiles/web/package.json`), but this ordering was verified statically only.
4. **Provider name.** `"spawn"` is the base default. It is now a config key
   (`provider`); if the deployment changes it, the value must match a registered provider
   or the tools reject with a "provider not registered" message.
5. **`agentOptions` capability.** Passing `{ maxTokens }` requires the provider's
   `agentOptions` capability. `spawn` advertises it
   (`@deepseek-ai/dsh-subagent-spawn-in-process/lib/index.js`, `capabilities`). A provider
   swap without that capability causes a loud start rejection (by design), not silent
   degradation.
6. **Semantic change in the three agent tools.** They now create a real child agent with
   its own session/lineage under the caller's session, rather than a standalone titled
   session. The tool schemas and text output contract are unchanged, but the child does not
   inherit the parent's conversation (it is a `spawn`, not a `fork`). Any downstream logic
   that assumed the old session title is not preserved; no such dependency was found in
   `plugins/`.
7. **Validator reach.** `ctx.web.fetch` cannot send auth headers/bodies/methods, so
   authenticated findings rely on the curl path. curl requires `/usr/bin/curl`
   (present: 8.7.1) and process-spawn permission in the live sandbox. If the sandbox denies
   spawning, the validator returns `CURL_SPAWN_FAILED`/`CURL_EXIT_*` structured errors
   instead of validating. Sandbox spawn behaviour inside the running host was not tested.
8. **Validator failure shape is a successful tool result.** Per the "never throw on a
   network error" requirement, transport/parse failures return a JSON string with
   `validated:false` and an `error` object rather than raising an `isError`. Callers must
   inspect `error`; the UI will show a successful call.
9. **Event payload grew.** `finding/validation` now also carries `statuses` and
   `transports` (success) and `error` (failure). Additive; a strict schema consumer of the
   old payload could notice.
10. **`ctx.emit` for an undeclared event.** `finding/validation` is not in any package's
    `Events` interface; it works at runtime (`events.d.ts:142`) but is untyped. This was
    already the case before the fix.
11. **Relative dirs.** `phasesDir`/`playbooksDir` (`./recon/phases`, `./playbooks`) still
    resolve against the server process cwd. Unchanged, and not re-verified in-process.

---

## 5. Files changed

| File | Change |
|---|---|
| `plugins/dsh-recon-orchestrator/index.js` | `sessions.create().run()` → `ctx.subagents.start()`; `inject` gains `subagents`, drops `sessions`; adds `provider`/`maxTokens` config |
| `plugins/dsh-finding-validator/index.js` | `ctx.tools.call("http_request", …)` → `ctx.web.fetch()` with `curl` fallback; structured, non-throwing errors; diff semantics preserved |
| `plugins/dsh-chain-builder/index.js` | `sessions.create().run()` → `ctx.subagents.start()`; `inject` updated |
| `plugins/dsh-report-writer/index.js` | `sessions.create().run()` → `ctx.subagents.start()`; `inject` updated |
| `plugins/_selftest.mjs` | **new** — offline mock-`ctx` harness, 21 tests |
| `plugins/PLUGIN-FIXES.md` | **new** — this report |
