#!/usr/bin/env node
/**
 * Offline self-test for the repaired bug-bounty pipeline plugins.
 *
 * It imports each fixed plugin module, builds a MOCK cordis `ctx` exposing only
 * the services/methods the plugin actually uses, calls `apply()`, captures the
 * registered tool, and invokes `execute()` with representative arguments —
 * including error paths.
 *
 * Network use is loopback-only (`node:http` on 127.0.0.1) so the curl transport
 * is exercised without contacting any external host. No bug-bounty target is
 * touched and the running DSH server is never involved.
 *
 * Run: node plugins/_selftest.mjs
 */
import assert from "node:assert/strict";
import http from "node:http";
import { createServer } from "node:http";
import { createSocket } from "node:dgram";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { mkdtemp, mkdir, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");

const results = [];

async function test(name, fn) {
  try {
    await fn();
    results.push({ ok: true, name });
    console.log(`PASS  ${name}`);
  } catch (error) {
    results.push({ ok: false, name, error });
    const detail = error && error.stack ? error.stack : String(error);
    console.log(`FAIL  ${name}\n${detail.split("\n").map((l) => `      ${l}`).join("\n")}`);
  }
}

function load(rel) {
  return import(pathToFileURL(join(ROOT, rel)).href);
}

/** Minimal cordis Context stand-in: only what these plugins call. */
function makeCtx({ web, subagents } = {}) {
  const tools = new Map();
  const events = [];
  const ctx = {
    tools: {
      register(definition) {
        tools.set(definition.name, definition);
        return () => tools.delete(definition.name);
      },
    },
    emit(name, payload) {
      events.push({ name, payload });
    },
    get(name) {
      if (name === "web") return web;
      if (name === "subagents") return subagents;
      return undefined;
    },
    logger: { info() {}, warn() {}, error() {} },
  };
  return { ctx, tools, events };
}

/** Minimal ctx.subagents stand-in recording request/dispose, with knob-driven outcomes. */
function makeSubagents({ output = "SUBAGENT TEXT", stopReason = "completed", diagnostic, startError, providers = ["spawn", "fork"] } = {}) {
  const calls = [];
  const disposed = [];
  const runtime = {
    list: () => [...providers],
    getProvider: (name) => (providers.includes(name) ? { name } : undefined),
    async start(provider, request) {
      calls.push({ provider, request });
      if (startError) throw startError;
      return {
        id: "child-1",
        localAgent: undefined,
        result: Promise.resolve({
          output: output === null ? [] : [{ type: "text", text: output }],
          stopReason,
          ...(diagnostic === undefined ? {} : { diagnostic }),
        }),
        async dispose() {
          disposed.push(true);
        },
      };
    },
  };
  return { runtime, calls, disposed };
}

const AGENT = { id: "session-parent", agent: true };
function makeExec(agent = AGENT) {
  return { callId: "call-1", name: "test", arguments: {}, agent, signal: new AbortController().signal };
}

const plugins = {};

async function main() {
  console.log(`offline self-test — ${new Date().toISOString()}`);
  console.log(`repo: ${ROOT}\n`);

  // ---------------------------------------------------------------- imports
  await test("all plugin modules import and export {name, inject, apply}", async () => {
    for (const rel of [
      "plugins/dsh-recon-orchestrator/index.js",
      "plugins/dsh-finding-validator/index.js",
      "plugins/dsh-chain-builder/index.js",
      "plugins/dsh-report-writer/index.js",
      "plugins/dsh-skill-loader/index.js",
      "plugins/dsh-skill-admission/index.js",
      "plugins/dsh-scope-guard/index.js",
      "plugins/dsh-hunt-journal/index.js",
      "plugins/dsh-triage-gate/index.js",
      "plugins/dsh-js-analyzer/index.js",
      "plugins/dsh-coverage/index.js",
      "plugins/dsh-claim-audit/index.js",
      "plugins/dsh-oob/index.js",
      "plugins/dsh-validators/index.js",
      "plugins/dsh-asset-dedup/index.js",
      "plugins/dsh-browser-validate/index.js",
      "plugins/dsh-skill-rag/index.js",
      "plugins/dsh-eval/index.js",
      "plugins/dsh-scope-intake/index.js",
      "plugins/dsh-proxy/index.js",
    ]) {
      const mod = await load(rel);
      assert.equal(typeof mod.name, "string", `${rel} name`);
      assert.ok(Array.isArray(mod.inject), `${rel} inject`);
      assert.equal(typeof mod.apply, "function", `${rel} apply`);
      plugins[mod.name] = mod;
    }
  });

  // ------------------------------------------------- dsh-recon-orchestrator
  await test("run_recon_phase calls ctx.subagents.start and returns child text", async () => {
    const { runtime, calls, disposed } = makeSubagents({ output: '{"phase":"01"}' });
    const { ctx, tools } = makeCtx({ subagents: runtime });
    plugins["recon-orchestrator"].apply(ctx);
    const tool = tools.get("run_recon_phase");
    assert.ok(tool, "run_recon_phase registered");

    const value = await tool.execute({ phase: "01", domain: "example.com" }, makeExec());
    assert.equal(value, '{"phase":"01"}');
    assert.equal(calls.length, 1);
    assert.equal(calls[0].provider, "spawn");
    assert.equal(calls[0].request.parent, AGENT);
    assert.equal(calls[0].request.signal instanceof AbortSignal, true);
    assert.equal(calls[0].request.agentOptions.maxTokens, 30000);
    assert.equal(calls[0].request.prompt[0].type, "text");
    assert.match(calls[0].request.prompt[0].text, /phase 01 on example\.com/);
    assert.match(calls[0].request.prompt[0].text, /\.\/recon\/phases\/01\.md/);
    assert.equal(calls[0].request.label, "recon 01 example.com");
    assert.equal(disposed.length, 1, "run disposed");
  });

  await test("run_recon_phase propagates a non-completed stop reason", async () => {
    const { runtime, disposed } = makeSubagents({ stopReason: "error", diagnostic: "model exploded" });
    const { ctx, tools } = makeCtx({ subagents: runtime });
    plugins["recon-orchestrator"].apply(ctx);
    await assert.rejects(
      () => tools.get("run_recon_phase").execute({ phase: "02", domain: "example.com" }, makeExec()),
      /ended abnormally \(error\)[\s\S]*model exploded/
    );
    assert.equal(disposed.length, 1, "run disposed even on failure");
  });

  await test("run_recon_phase rejects without a calling agent (exec.agent undefined)", async () => {
    const { runtime } = makeSubagents();
    const { ctx, tools } = makeCtx({ subagents: runtime });
    plugins["recon-orchestrator"].apply(ctx);
    const exec = makeExec();
    delete exec.agent;
    await assert.rejects(
      () => tools.get("run_recon_phase").execute({ phase: "01", domain: "example.com" }, exec),
      /requires a calling agent/
    );
  });

  await test("run_recon_phase rejects when the subagents service is absent", async () => {
    const { ctx, tools } = makeCtx({});
    plugins["recon-orchestrator"].apply(ctx);
    await assert.rejects(
      () => tools.get("run_recon_phase").execute({ phase: "01", domain: "example.com" }, makeExec()),
      /requires the `subagents` service/
    );
  });

  await test("run_recon_phase rejects when the configured provider is not registered", async () => {
    const { runtime } = makeSubagents({ providers: ["fork"] });
    const { ctx, tools } = makeCtx({ subagents: runtime });
    plugins["recon-orchestrator"].apply(ctx);
    await assert.rejects(
      () => tools.get("run_recon_phase").execute({ phase: "01", domain: "example.com" }, makeExec()),
      /provider "spawn" is not registered; available: fork/
    );
  });

  // ------------------------------------------------------- dsh-chain-builder
  await test("build_chain reads playbooks, calls the child, and returns its text", async () => {
    const { runtime, calls } = makeSubagents({ output: "CHAIN: A -> B -> C" });
    const { ctx, tools } = makeCtx({ subagents: runtime });
    plugins["chain-builder"].apply(ctx, { playbooksDir: join(ROOT, "playbooks") });
    const tool = tools.get("build_chain");
    assert.ok(tool, "build_chain registered");

    const value = await tool.execute(
      { findings: JSON.stringify([{ id: "f-1", title: "IDOR" }]) },
      makeExec()
    );
    assert.equal(value, "CHAIN: A -> B -> C");
    assert.equal(calls[0].request.agentOptions.maxTokens, 20000);
    assert.equal(calls[0].request.label, "chain-build");
    assert.match(calls[0].request.prompt[0].text, /f-1/);
    assert.match(calls[0].request.prompt[0].text, /Playbooks:/);
    assert.ok(calls[0].request.prompt[0].text.length > 1000, "playbook bodies embedded");
  });

  await test("build_chain rejects on malformed findings JSON", async () => {
    const { runtime } = makeSubagents();
    const { ctx, tools } = makeCtx({ subagents: runtime });
    plugins["chain-builder"].apply(ctx, { playbooksDir: join(ROOT, "playbooks") });
    await assert.rejects(
      () => tools.get("build_chain").execute({ findings: "{not json" }, makeExec()),
      SyntaxError
    );
  });

  // ------------------------------------------------------- dsh-report-writer
  await test("write_report calls the child with the finding and optional chain", async () => {
    const { runtime, calls } = makeSubagents({ output: "# Title\nreport body" });
    const { ctx, tools } = makeCtx({ subagents: runtime });
    plugins["report-writer"].apply(ctx);
    const tool = tools.get("write_report");
    assert.ok(tool, "write_report registered");

    const value = await tool.execute(
      { finding: JSON.stringify({ id: "F-7" }), chain: JSON.stringify({ steps: ["A", "B"] }) },
      makeExec()
    );
    assert.equal(value, "# Title\nreport body");
    assert.equal(calls[0].request.label, "report F-7");
    assert.equal(calls[0].request.agentOptions.maxTokens, 60000);
    assert.match(calls[0].request.prompt[0].text, /HackerOne report/);
    assert.match(calls[0].request.prompt[0].text, /"steps":\["A","B"\]/);
  });

  await test("write_report works without a chain and rejects on malformed finding JSON", async () => {
    const { runtime, calls } = makeSubagents();
    const { ctx, tools } = makeCtx({ subagents: runtime });
    plugins["report-writer"].apply(ctx);
    const tool = tools.get("write_report");
    await tool.execute({ finding: JSON.stringify({ id: "F-8" }) }, makeExec());
    assert.match(calls[0].request.prompt[0].text, /Chain: null/);
    await assert.rejects(() => tool.execute({ finding: "nope{" }, makeExec()), SyntaxError);
  });

  await test("write_report rejects when the subagents service is absent", async () => {
    const { ctx, tools } = makeCtx({});
    plugins["report-writer"].apply(ctx);
    await assert.rejects(
      () => tools.get("write_report").execute({ finding: JSON.stringify({ id: "F-9" }) }, makeExec()),
      /requires the `subagents` service/
    );
  });

  // --------------------------------------------------- dsh-finding-validator
  await test("validate_finding diffs baseline vs probe through the ctx.web seam", async () => {
    const web = {
      async fetch({ url }) {
        if (url.endsWith("/baseline")) {
          return { url, statusCode: 200, body: { kind: "text", content: "hello" }, truncated: false };
        }
        return { url, statusCode: 500, body: { kind: "text", content: "hello!" }, truncated: false };
      },
    };
    const { ctx, tools, events } = makeCtx({ web });
    plugins["finding-validator"].apply(ctx);
    const tool = tools.get("validate_finding");
    assert.ok(tool, "validate_finding registered");

    const value = await tool.execute(
      {
        baseline: JSON.stringify({ url: "https://target.test/baseline" }),
        probe: JSON.stringify({ url: "https://target.test/probe" }),
      },
      makeExec()
    );
    const parsed = JSON.parse(value);
    assert.deepEqual(parsed.diff, { statusChanged: true, lengthDelta: 1, bodyDiffers: true });
    assert.equal(parsed.validated, true);
    assert.equal(parsed.error, undefined);
    const event = events.find((e) => e.name === "finding/validation");
    assert.ok(event, "finding/validation emitted");
    assert.deepEqual(event.payload.transports, { baseline: "web", probe: "web" });
    assert.deepEqual(event.payload.statuses, { baseline: 200, probe: 500 });
    assert.equal(event.payload.validated, true);
  });

  await test("validate_finding reports validated=false for identical responses (no throw)", async () => {
    const web = {
      async fetch({ url }) {
        return { url, statusCode: 200, body: { kind: "text", content: "same" }, truncated: false };
      },
    };
    const { ctx, tools } = makeCtx({ web });
    plugins["finding-validator"].apply(ctx);
    const value = await tools.get("validate_finding").execute(
      {
        baseline: JSON.stringify({ url: "https://target.test/x" }),
        probe: JSON.stringify({ url: "https://target.test/y" }),
      },
      makeExec()
    );
    const parsed = JSON.parse(value);
    assert.deepEqual(parsed.diff, { statusChanged: false, lengthDelta: 0, bodyDiffers: false });
    assert.equal(parsed.validated, false);
    // Enrichment over the original spec: noise-aware fields sit alongside
    // the raw diff rather than replacing it, so a caller can tell "no raw
    // diff" apart from "raw diff but it's noise".
    assert.equal(parsed.normalizedBodyDiffers, false);
    assert.equal(parsed.confidence, "none");
  });

  await test("validate_finding returns a structured error when the web provider rejects the URL", async () => {
    const web = {
      async fetch() {
        const error = new Error("URL hostname resolves to a non-public IP address");
        error.code = "WEB_BLOCKED_URL";
        throw error;
      },
    };
    const { ctx, tools, events } = makeCtx({ web });
    plugins["finding-validator"].apply(ctx);
    const value = await tools.get("validate_finding").execute(
      {
        baseline: JSON.stringify({ url: "http://127.0.0.1:9/admin" }),
        probe: JSON.stringify({ url: "http://127.0.0.1:9/admin?x=1" }),
      },
      makeExec()
    );
    const parsed = JSON.parse(value);
    assert.equal(parsed.validated, false);
    assert.equal(parsed.error.code, "WEB_BLOCKED_URL");
    assert.match(parsed.error.message, /non-public IP/);
    assert.equal(parsed.statuses.baseline, null);
    assert.ok(events.some((e) => e.name === "finding/validation"));
  });

  await test("validate_finding returns structured errors for malformed JSON and bad request shapes", async () => {
    const { ctx, tools } = makeCtx({});
    plugins["finding-validator"].apply(ctx);
    const tool = tools.get("validate_finding");

    const badBaseline = JSON.parse(
      await tool.execute({ baseline: "{oops", probe: JSON.stringify({ url: "https://target.test/" }) }, makeExec())
    );
    assert.equal(badBaseline.validated, false);
    assert.equal(badBaseline.error.code, "BASELINE_JSON_PARSE");

    const badProbe = JSON.parse(
      await tool.execute({ baseline: JSON.stringify({ url: "https://target.test/" }), probe: "nope" }, makeExec())
    );
    assert.equal(badProbe.error.code, "PROBE_JSON_PARSE");

    const noUrl = JSON.parse(
      await tool.execute(
        { baseline: JSON.stringify({ note: "no url here" }), probe: JSON.stringify({ url: "https://target.test/" }) },
        makeExec()
      )
    );
    assert.equal(noUrl.error.code, "INVALID_REQUEST");
    assert.match(noUrl.error.message, /missing a non-empty `url`/);
  });

  await test("validate_finding rejects a malformed web response instead of inventing a diff", async () => {
    const web = {
      async fetch() {
        return {};
      },
    };
    const { ctx, tools } = makeCtx({ web });
    plugins["finding-validator"].apply(ctx);
    const parsed = JSON.parse(
      await tools.get("validate_finding").execute(
        {
          baseline: JSON.stringify({ url: "https://target.test/a" }),
          probe: JSON.stringify({ url: "https://target.test/b" }),
        },
        makeExec()
      )
    );
    assert.equal(parsed.validated, false);
    assert.equal(parsed.error.code, "WEB_BAD_RESPONSE");
  });

  await test("validate_finding curl fallback fails cleanly when curl cannot connect (loopback, no external traffic)", async () => {
    // No ctx.web -> the curl fallback is selected for a plain GET.
    const { ctx, tools } = makeCtx({});
    plugins["finding-validator"].apply(ctx);
    const value = await tools.get("validate_finding").execute(
      {
        baseline: JSON.stringify({ url: "http://127.0.0.1:1/baseline" }),
        probe: JSON.stringify({ url: "http://127.0.0.1:1/probe" }),
      },
      makeExec()
    );
    const parsed = JSON.parse(value);
    assert.equal(parsed.validated, false);
    assert.match(parsed.error.code, /^CURL_/);
    assert.equal(parsed.transports.baseline, "curl");
    assert.equal(parsed.statuses.baseline, null);
  });

  await test("validate_finding curl fallback honours explicit method/headers and diffs status+body", async () => {
    const server = createServer((req, res) => {
      if (req.method === "POST") {
        let body = "";
        req.on("data", (c) => (body += c));
        req.on("end", () => {
          res.writeHead(201, { "content-type": "text/plain", "x-echo": req.headers["x-probe-token"] || "" });
          res.end(`posted:${body}`);
        });
        return;
      }
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("plain");
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = server.address().port;
    try {
      const { ctx, tools, events } = makeCtx({});
      plugins["finding-validator"].apply(ctx);
      const value = await tools.get("validate_finding").execute(
        {
          baseline: JSON.stringify({ url: `http://127.0.0.1:${port}/plain` }),
          probe: JSON.stringify({
            url: `http://127.0.0.1:${port}/echo`,
            method: "POST",
            headers: { "x-probe-token": "abc123" },
            body: "payload",
          }),
        },
        makeExec()
      );
      const parsed = JSON.parse(value);
      assert.equal(parsed.validated, true);
      // "plain" (5) vs "posted:payload" (14) -> delta 9
      assert.deepEqual(parsed.diff, { statusChanged: true, lengthDelta: 9, bodyDiffers: true });
      const event = events.find((e) => e.name === "finding/validation");
      assert.deepEqual(event.payload.statuses, { baseline: 200, probe: 201 });
      assert.deepEqual(event.payload.transports, { baseline: "curl", probe: "curl" });
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  await test("validate_finding curl fallback handles an explicit HEAD without hanging", async () => {
    const server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("body-that-head-must-not-return");
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = server.address().port;
    try {
      const { ctx, tools, events } = makeCtx({});
      plugins["finding-validator"].apply(ctx, { timeoutMs: 5000 });
      const parsed = JSON.parse(
        await tools.get("validate_finding").execute(
          {
            baseline: JSON.stringify({ url: `http://127.0.0.1:${port}/h`, method: "HEAD" }),
            probe: JSON.stringify({ url: `http://127.0.0.1:${port}/h`, method: "HEAD" }),
          },
          makeExec()
        )
      );
      assert.equal(parsed.validated, false);
      assert.equal(parsed.error, undefined);
      const event = events.find((e) => e.name === "finding/validation");
      assert.deepEqual(event.payload.statuses, { baseline: 200, probe: 200 });
      assert.deepEqual(event.payload.transports, { baseline: "curl", probe: "curl" });
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  await test("validate_finding prefers curl when the web seam cannot express the request", async () => {
    const server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = server.address().port;
    let webCalls = 0;
    const web = {
      async fetch({ url }) {
        webCalls += 1;
        return { url, statusCode: 200, body: { kind: "text", content: "ok" }, truncated: false };
      },
    };
    try {
      const { ctx, tools, events } = makeCtx({ web });
      plugins["finding-validator"].apply(ctx);
      await tools.get("validate_finding").execute(
        {
          baseline: JSON.stringify({ url: `http://127.0.0.1:${port}/a`, headers: { authorization: "Bearer t" } }),
          probe: JSON.stringify({ url: `http://127.0.0.1:${port}/b`, headers: { authorization: "Bearer t" } }),
        },
        makeExec()
      );
      assert.equal(webCalls, 0, "web seam skipped for header-bearing requests");
      const event = events.find((e) => e.name === "finding/validation");
      assert.deepEqual(event.payload.transports, { baseline: "curl", probe: "curl" });
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  // ------------------------------------------------------- dsh-skill-loader
  await test("load_skills_for_target still works (regression guard)", async () => {
    const { ctx, tools } = makeCtx({});
    plugins["skill-loader"].apply(ctx, { skillsRoot: join(ROOT, "skills") });
    const tool = tools.get("load_skills_for_target");
    assert.ok(tool, "load_skills_for_target registered");
    const parsed = JSON.parse(await tool.execute({ profile: "wordpress graphql jwt idor" }, makeExec()));
    assert.equal(typeof parsed.master, "string");
    assert.ok(parsed.master.length > 0, "master skill body loaded");
    assert.ok(parsed.count <= 3, "max 3 skills per hunt");
    assert.ok(Array.isArray(parsed.skills));
  });

  // ----------------------------------------------------- dsh-skill-admission
  // Regression coverage for the h1-classifier -> skill-admission wiring:
  // candidates must be staged OUTSIDE skills/learned/ before dedupe runs, or
  // dedupe's own directory scan will match a candidate against itself.
  const admissionTmp = await mkdtemp(join(tmpdir(), "bughive-admission-"));
  const admissionRoot = join(admissionTmp, "skills");
  await mkdir(join(admissionRoot, "seeds"), { recursive: true });
  await mkdir(join(admissionRoot, "learned"), { recursive: true });
  await mkdir(join(admissionRoot, "staging"), { recursive: true });

  const wellFormedSkill = (
    "## Trigger Conditions\nAny endpoint returning a JWT.\n" +
    "## Root Cause Pattern\nMissing signature verification allows algorithm confusion.\n" +
    "## Recon Checklist\n- Find endpoints issuing JWTs\n" +
    "## Hunt Methodology\n1. Decode the JWT header, try alg:none\n" +
    "## Payload Patterns\n{\"alg\":\"none\"}\n" +
    "## WAF Bypass Tips\nCase variation on header name\n" +
    "## Triage Guidance\nFull bypass -> Critical\n" +
    "## Example\nhttps://hackerone.com/reports/999999\n"
  ).repeat(2);

  await test("validate_skill_candidate admits a well-formed, in-budget candidate", async () => {
    const { ctx, tools } = makeCtx({});
    plugins["skill-admission"].apply(ctx, { skillsRoot: admissionRoot });
    const stagingPath = join(admissionRoot, "staging", "h1-347-999999.md");
    await writeFile(stagingPath, wellFormedSkill);
    const parsed = JSON.parse(
      await tools.get("validate_skill_candidate").execute(
        { path: stagingPath, cwe: "347", severity: "high", bounty: 500, source: "https://hackerone.com/reports/999999" },
        makeExec()
      )
    );
    assert.equal(parsed.admitted, true);
    assert.ok(parsed.tokens >= 200 && parsed.tokens <= 1000, "within the 200-1000 token budget");
    const written = await readFile(stagingPath, "utf-8");
    assert.ok(written.startsWith("---"), "frontmatter written on admission");
  });

  await test("validate_skill_candidate rejects a candidate missing required sections", async () => {
    const { ctx, tools } = makeCtx({});
    plugins["skill-admission"].apply(ctx, { skillsRoot: admissionRoot });
    const stagingPath = join(admissionRoot, "staging", "h1-79-111111.md");
    await writeFile(stagingPath, "## Trigger Conditions\nsomething\n## Example\nhttps://hackerone.com/reports/1\n");
    const parsed = JSON.parse(
      await tools.get("validate_skill_candidate").execute(
        { path: stagingPath, cwe: "79", severity: "low", bounty: 0, source: "https://hackerone.com/reports/1" },
        makeExec()
      )
    );
    assert.equal(parsed.admitted, false);
    assert.ok(parsed.failures.some((f) => f.includes("missing sections")));
  });

  await test("dedupe_skill_candidate does not self-match when staged outside the scanned library", async () => {
    const { ctx, tools } = makeCtx({});
    plugins["skill-admission"].apply(ctx, { skillsRoot: admissionRoot });
    // Library is still empty at this point in the admission test above's
    // staging path (learned/ only gets the promoted copy, never tested here) --
    // scanning learned/ + seeds/ should find nothing matching a file that
    // only exists in staging/.
    const stagingPath = join(admissionRoot, "staging", "h1-347-999999.md");
    const parsed = JSON.parse(
      await tools.get("dedupe_skill_candidate").execute({ path: stagingPath, cwe: "347" }, makeExec())
    );
    assert.equal(parsed.duplicate, false);
    assert.equal(parsed.candidates_checked, 0, "staging/ candidates must not be scanned as part of the library");
  });

  await test("dedupe_skill_candidate flags a near-duplicate once the original is promoted into learned/", async () => {
    const { ctx, tools } = makeCtx({});
    plugins["skill-admission"].apply(ctx, { skillsRoot: admissionRoot });
    // Promote the well-formed candidate from the admission test into learned/,
    // simulating what h1-classifier does after a passing admission check.
    await writeFile(join(admissionRoot, "learned", "h1-347-999999.md"), wellFormedSkill);
    const dupPath = join(admissionRoot, "staging", "h1-347-888888.md");
    await writeFile(dupPath, wellFormedSkill.replace(/999999/g, "888888"));
    const parsed = JSON.parse(
      await tools.get("dedupe_skill_candidate").execute({ path: dupPath, cwe: "347" }, makeExec())
    );
    assert.equal(parsed.duplicate, true);
    assert.equal(parsed.closest, "learned/h1-347-999999.md");
  });

  // ------------------------------------------------------------ scope-guard
  await test("scope_check matches wildcard patterns, honours exclusions, defaults to deny", async () => {
    const { ctx, tools } = makeCtx({});
    plugins["scope-guard"].apply(ctx);
    const check = tools.get("scope_check");
    assert.ok(check, "scope_check registered");
    const scope = "safe-*.threema.ch\napip.threema.ch\n!safe-99.threema.ch";

    const q = async (t) => JSON.parse(await check.execute({ scope, target: t }));

    assert.equal((await q("safe-10.threema.ch")).allowed, true, "wildcard matches one label");
    // `*` must NOT cross a dot -- this is the whole point of the plugin.
    assert.equal((await q("safe-10.0.threema.ch")).allowed, false, "wildcard must not cross a dot");
    assert.equal((await q("apip.threema.ch")).allowed, true, "exact host matches");
    assert.equal((await q("safe-99.threema.ch")).allowed, false, "exclusion always wins");
    assert.equal((await q("evil.example")).allowed, false, "default deny");
    assert.equal((await q("sub.apip.threema.ch")).allowed, false, "no implicit subdomain match");

    // Normalisation: URLs, ports and trailing dots resolve to the same host.
    assert.equal((await q("https://apip.threema.ch/en/login?x=1")).allowed, true, "URL normalised");
    assert.equal((await q("apip.threema.ch:443")).allowed, true, "port stripped");

    const empty = JSON.parse(await check.execute({ scope: "", target: "apip.threema.ch" }));
    assert.equal(empty.allowed, false, "empty scope document is default-deny");
  });

  await test("scope_assert splits targets into allowed and refused", async () => {
    const { ctx, tools } = makeCtx({});
    plugins["scope-guard"].apply(ctx);
    const res = JSON.parse(
      await tools.get("scope_assert").execute({
        scope: "apip.threema.ch\ng-*.0.threema.ch",
        targets: "apip.threema.ch\ng-2a.0.threema.ch\napi.threema.ch\nmsgapi.threema.ch",
      })
    );
    assert.equal(res.safe, false, "out-of-scope targets must be reported unsafe");
    assert.equal(res.allowed.length, 2, "two in-scope hosts allowed");
    assert.equal(res.refused.length, 2, "two out-of-scope hosts refused");
    assert.deepEqual(res.allowed.sort(), ["apip.threema.ch", "g-2a.0.threema.ch"]);
    assert.ok(res.refused.every((r) => typeof r.reason === "string" && r.reason.length > 0));
  });

  // ----------------------------------------------------------- hunt-journal
  await test("hunt_journal persists events and derives open leads", async () => {
    const huntsRoot = await mkdtemp(join(tmpdir(), "bh-journal-"));
    const { ctx, tools } = makeCtx({});
    plugins["hunt-journal"].apply(ctx, { huntsRoot });

    const append = tools.get("hunt_journal_append");
    await append.execute({ domain: "example.test", kind: "lead", summary: "try /api/v2/users" });
    await append.execute({ domain: "example.test", kind: "deadend", summary: "admin is IP-restricted" });
    await append.execute({ domain: "example.test", kind: "request", summary: "GET / -> 200" });

    const stats = JSON.parse(await tools.get("hunt_journal_stats").execute({ domain: "example.test" }));
    assert.equal(stats.total, 3);
    assert.equal(stats.by_kind.lead, 1);
    assert.equal(stats.by_kind.request, 1);

    const leads = JSON.parse(await tools.get("hunt_journal_leads").execute({ domain: "example.test" }));
    assert.equal(leads.open_leads, 1, "only the un-retracted lead is open");

    // A lead later marked as a dead end stops being listed as open.
    await append.execute({ domain: "example.test", kind: "deadend", summary: "try /api/v2/users" });
    const after = JSON.parse(await tools.get("hunt_journal_leads").execute({ domain: "example.test" }));
    assert.equal(after.open_leads, 0, "dead-ended lead is no longer open");

    const tail = JSON.parse(
      await tools.get("hunt_journal_tail").execute({ domain: "example.test", kind: "request", limit: 5 })
    );
    assert.equal(tail.events.length, 1, "kind filter applies");

    // Unknown kind is rejected rather than silently written.
    const bad = JSON.parse(await append.execute({ domain: "example.test", kind: "nonsense", summary: "x" }));
    assert.equal(bad.appended, false);

    // Ingest (proxy history): harvest request evidence from recon output, idempotently.
    const reconDir = join(huntsRoot, "example.test", "recon");
    await mkdir(reconDir, { recursive: true });
    await writeFile(
      join(reconDir, "summary.json"),
      JSON.stringify({ phase: "04", items: [{ url: "https://a.example.test/api/users?id=1" }] })
    );
    const first = JSON.parse(
      await tools.get("hunt_journal_ingest").execute({ domain: "example.test", paths: reconDir })
    );
    assert.equal(first.newly_ingested, 1, "harvested one request");
    const second = JSON.parse(
      await tools.get("hunt_journal_ingest").execute({ domain: "example.test", paths: reconDir })
    );
    assert.equal(second.newly_ingested, 0, "re-ingest must be idempotent");
    assert.equal(second.already_journaled, 1);

    // A hunt with no journal yet reads as empty, not as an error.
    const missing = JSON.parse(await tools.get("hunt_journal_stats").execute({ domain: "nothing.test" }));
    assert.equal(missing.total, 0);
  });

  // ------------------------------------------------------------ triage-gate
  await test("triage_gate passes a clean finding and kills rejected classes", async () => {
    const { ctx, tools } = makeCtx({});
    plugins["triage-gate"].apply(ctx);
    const gate = tools.get("triage_gate");
    const yes = {
      q1Reproducible: true,
      q2ImpactAccepted: true,
      q3InScope: true,
      q4NoPrivilegedAccess: true,
      q5NotKnown: true,
      q6ProvenImpact: true,
      q7NotAlwaysRejected: true,
    };
    const run = async (o) => JSON.parse(await gate.execute(o));

    const ok = await run({
      title: "IDOR in /api/v1/users/{id} allows any tenant to read another tenant's credentials",
      impact: "cross-tenant read of cleartext credential passwords",
      answers: JSON.stringify(yes),
    });
    assert.equal(ok.passed, true, "clean finding passes");
    assert.equal(ok.cvss.severity, "Medium", "conservative CVSS hint");

    // A single NO kills it.
    const oneNo = await run({
      title: "IDOR somewhere",
      impact: "unclear",
      answers: JSON.stringify({ ...yes, q6ProvenImpact: false }),
    });
    assert.equal(oneNo.passed, false);
    assert.ok(oneNo.failures.some((f) => f.startsWith("q6ProvenImpact")));

    // Missing answers count as NO, not as skipped.
    const missing = await run({ title: "anything", answers: "{}" });
    assert.equal(missing.passed, false);
    assert.equal(missing.failures.length, 7);

    // Always-rejected class without a chain is killed...
    const noChain = await run({
      title: "Open redirect in /login?r=",
      impact: "redirects the user elsewhere",
      answers: JSON.stringify(yes),
    });
    assert.equal(noChain.passed, false);
    assert.ok(noChain.failures.some((f) => f.includes("without a demonstrated chain")));

    // ...but passes once a real chain is demonstrated.
    const chained = await run({
      title: "Open redirect in /login?r= chains to OAuth code theft",
      impact: "account takeover",
      answers: JSON.stringify(yes),
      hasChain: true,
      chain: "r= attacker origin -> auth code leaked -> ATO",
    });
    assert.equal(chained.passed, true, "chain requirement satisfied");

    // Non-chain rejected classes fail outright.
    const header = await run({
      title: "Missing HSTS header on the cockpit",
      impact: "downgrade risk",
      answers: JSON.stringify(yes),
    });
    assert.equal(header.passed, false);

    // Malformed gate input is a hard kill, never a throw.
    const broken = await run({ title: "x", answers: "not json" });
    assert.equal(broken.passed, false);
  });

  // ---------------------------------------------------------- js-analyzer
  await test("analyze_js flags a client-side redirect allowlist, DOM sink, and extracts endpoints", async () => {
    const dir = await mkdtemp(join(tmpdir(), "bh-js-"));
    await writeFile(
      join(dir, "app.js"),
      [
        'const TRUSTED_REDIRECT_ORIGINS = JSON.parse(meta["trusted_redirect_origins"].content);',
        "function validateSameOriginUrl(u){ return originMatchesPattern(u); }",
        "el.innerHTML = userInput;",
        'const p = "/api/v1/users";',
        'if (user.role === "admin") { doThing(); }',
      ].join("\n") + "\n"
    );
    const { ctx, tools } = makeCtx({});
    plugins["js-analyzer"].apply(ctx);
    const res = JSON.parse(await tools.get("analyze_js").execute({ paths: dir }));
    const rules = res.findings.map((f) => f.rule);
    assert.ok(rules.includes("redirect-allowlist"), "redirect allowlist detected");
    assert.ok(rules.includes("dom-xss-sink"), "DOM XSS sink detected");
    assert.equal(res.files_scanned, 1);
    assert.ok(res.endpoints.includes("/api/v1/users"), "endpoint extracted");
    // Every lead must carry an actionable next step.
    assert.ok(res.findings.every((f) => typeof f.next_step === "string" && f.next_step.length > 10));

    // Severity filtering works.
    const highOnly = JSON.parse(await tools.get("analyze_js").execute({ paths: dir, minSeverity: "high" }));
    assert.ok(highOnly.findings.every((f) => f.severity === "high"));

    // Empty input is an error, not a crash.
    const none = JSON.parse(await tools.get("analyze_js").execute({ paths: "" }));
    assert.ok(none.error);
  });

  // ------------------------------------------------------------- coverage
  await test("coverage gates a hunt until critical cells are resolved, and demands reasons", async () => {
    const huntsRoot = await mkdtemp(join(tmpdir(), "bh-cov-"));
    await mkdir(join(huntsRoot, "example.test"), { recursive: true });
    await writeFile(join(huntsRoot, "example.test", "scope.txt"), "a.example.test\nb.example.test\n");
    const { ctx, tools } = makeCtx({});
    plugins["coverage"].apply(ctx, { huntsRoot, skillsRoot: join(ROOT, "skills") });

    const init = JSON.parse(
      await tools.get("coverage_init").execute({ domain: "example.test", classes: "idor,sqli" })
    );
    assert.equal(init.cells_total, 4, "2 classes x 2 assets");
    assert.equal(init.cells_created, 4);

    // Cold start: the gate must refuse a clean conclusion.
    const cold = JSON.parse(await tools.get("coverage_gate").execute({ domain: "example.test" }));
    assert.equal(cold.pass, false);
    assert.equal(cold.blocking_count, 4);

    // n/a and blocked require a reason -- this is the honesty mechanism.
    const refused = JSON.parse(
      await tools.get("coverage_mark").execute({
        domain: "example.test", vulnClass: "idor", asset: "a.example.test", status: "n/a",
      })
    );
    assert.equal(refused.marked, false, "n/a without a reason must be refused");
    const blocked = JSON.parse(
      await tools.get("coverage_mark").execute({
        domain: "example.test", vulnClass: "idor", asset: "b.example.test", status: "blocked",
        reason: "needs a second tenant account",
      })
    );
    assert.equal(blocked.marked, true);

    // Resolve the rest.
    await tools.get("coverage_mark").execute({
      domain: "example.test", vulnClass: "idor", asset: "a.example.test", status: "tested", identities: 2,
      evidence: "GET /x -> 403",
    });
    await tools.get("coverage_mark").execute({ domain: "example.test", vulnClass: "sqli", asset: "a.example.test", status: "tested" });
    await tools.get("coverage_mark").execute({ domain: "example.test", vulnClass: "sqli", asset: "b.example.test", status: "tested" });

    const gaps = JSON.parse(await tools.get("coverage_gaps").execute({ domain: "example.test", criticalOnly: true }));
    assert.equal(gaps.gaps_total, 0, "no unresolved critical cells once each is resolved");

    const warm = JSON.parse(await tools.get("coverage_gate").execute({ domain: "example.test" }));
    assert.equal(warm.pass, true);
    assert.equal(warm.critical_completion_pct, 100);

    const summary = JSON.parse(await tools.get("coverage_summary").execute({ domain: "example.test" }));
    assert.equal(summary.by_status.blocked, 1);
    assert.equal(summary.blocked[0].reason, "needs a second tenant account");

    // A hunt with no matrix cannot claim completeness.
    const missing = JSON.parse(await tools.get("coverage_gate").execute({ domain: "other.test" }));
    assert.equal(missing.pass, false);
  });

  // ----------------------------------------------------------- claim-audit
  await test("audit_report flags fabricated coverage, at endpoint and technique level", async () => {
    const dir = await mkdtemp(join(tmpdir(), "bh-audit-"));
    await writeFile(
      join(dir, "journal.jsonl"),
      [
        // fetch_bulk was requested, and with a real SQLi payload.
        JSON.stringify({ kind: "request", summary: "POST /identity/fetch_bulk -> 200" }),
        JSON.stringify({
          kind: "request",
          summary: "POST /identity/fetch_bulk -> 200",
          detail: { payload: "' OR '1'='1" },
        }),
        // create was requested, but only with a benign body -- no SQLi payload.
        JSON.stringify({ kind: "request", summary: "POST /identity/create -> 200" }),
      ].join("\n") + "\n"
    );
    const { ctx, tools } = makeCtx({});
    plugins["claim-audit"].apply(ctx);
    const audit = tools.get("audit_report");

    // The exact fabrication seen in this repo's history: one endpoint truly tested with
    // the claimed technique, four claimed.
    const report = "No SQLi indicators on POST /identity/fetch_bulk or POST /identity/check parameters.\n";
    const res = JSON.parse(await audit.execute({ reportText: report, evidencePaths: dir }));
    assert.equal(res.pass, false, "unbacked claim must fail the audit");
    const unsupported = res.unsupported.map((u) => u.endpoint);
    assert.ok(unsupported.some((e) => e.includes("/identity/check")), "never-requested endpoint flagged");
    assert.ok(!unsupported.some((e) => e.includes("/identity/fetch_bulk")), "truly tested endpoint not flagged");
    assert.ok(res.endpoints_never_requested.some((e) => e.includes("/identity/check")));

    // Technique-level: the endpoint WAS requested, but with no SQLi payload. Claiming
    // "SQLi tested here" off a plain GET is exactly the lie this must catch.
    const techReport = "SQLi was tested on POST /identity/create with no error difference.\n";
    const tech = JSON.parse(await audit.execute({ reportText: techReport, evidencePaths: dir }));
    assert.equal(tech.pass, false, "technique claim without a payload marker must fail");
    assert.equal(tech.unsupported[0].technique, "sqli");
    assert.ok(/payload marker/.test(tech.unsupported[0].reason));

    // A claim backed by a real payload passes.
    const good = "SQLi was tested on POST /identity/fetch_bulk using ' OR '1'='1 with no error.\n";
    const ok = JSON.parse(await audit.execute({ reportText: good, evidencePaths: dir }));
    assert.equal(ok.pass, true, "claim backed by endpoint + payload marker passes");

    // Techniques that cannot be proven from a payload string are reported honestly
    // rather than silently passing.
    const idorReport = "IDOR was tested on POST /identity/create.\n";
    const idor = JSON.parse(await audit.execute({ reportText: idorReport, evidencePaths: dir }));
    assert.ok(idor.unverifiable_count >= 1, "IDOR must be marked unverifiable");
    assert.equal(idor.unverifiable[0].technique, "idor");

    // No evidence at all is a hard fail, never a silent pass.
    const empty = await mkdtemp(join(tmpdir(), "bh-audit-empty-"));
    const noEv = JSON.parse(await audit.execute({ reportText: good, evidencePaths: empty }));
    assert.equal(noEv.pass, false);
    assert.ok(noEv.error);
  });

  // ------------------------------------------------------------------- oob
  await test("oob listener records real HTTP and DNS callbacks and correlates the token", async () => {
    const httpPort = 8710 + Math.floor(Math.random() * 180);
    const dnsPort = 9410 + Math.floor(Math.random() * 180);
    const { ctx, tools } = makeCtx({});
    plugins["oob"].apply(ctx, { httpPort, dnsPort, bindHost: "127.0.0.1", enableDns: true });

    const started = JSON.parse(await tools.get("oob_start").execute({}));
    assert.equal(started.started, true);
    let stopped = null;
    try {
      const mint = JSON.parse(await tools.get("oob_mint").execute({ note: "ssrf param" }));
      assert.ok(mint.token, "token minted");
      assert.ok(mint.url.includes(mint.token), "url carries the token");
      assert.ok(mint.dnsName.startsWith(mint.token), "dns name carries the token");

      // Real HTTP callback against the live listener (loopback only).
      const res = await fetch(mint.url);
      assert.equal(res.status, 200);
      const waited = JSON.parse(
        await tools.get("oob_wait").execute({ token: mint.token, timeoutMs: 3000, pollMs: 50 })
      );
      assert.equal(waited.confirmed, true, "http callback confirmed");
      assert.ok(waited.kinds.includes("http"));

      // Real DNS callback: hand-build a query for <token>.oob.local.
      // Use a SECOND token: oob_wait returns on the first matching interaction, so
      // reusing the HTTP token would short-circuit before the DNS packet arrives.
      const dnsMint = JSON.parse(await tools.get("oob_mint").execute({ note: "xxe entity" }));
      const labels = dnsMint.dnsName.split(".");
      const qname = [];
      for (const l of labels) qname.push(l.length, ...Buffer.from(l, "ascii"));
      qname.push(0);
      const pkt = Buffer.concat([
        Buffer.from([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
        Buffer.from(qname),
        Buffer.from([0x00, 0x01, 0x00, 0x01]),
      ]);
      await new Promise((resolve) => {
        const s = createSocket("udp4");
        s.send(pkt, dnsPort, "127.0.0.1", () => {
          s.close();
          resolve();
        });
      });
      const dnsWait = JSON.parse(
        await tools.get("oob_wait").execute({ token: dnsMint.token, timeoutMs: 3000, pollMs: 50 })
      );
      assert.ok(dnsWait.kinds.includes("dns"), "dns interaction captured");
      assert.equal(dnsWait.interactions[0].qname, dnsMint.dnsName, "dns qname correlated to the token");

      // An unknown token must never confirm.
      const miss = JSON.parse(
        await tools.get("oob_wait").execute({ token: "0000000000000000", timeoutMs: 300, pollMs: 50 })
      );
      assert.equal(miss.confirmed, false, "unknown token must not confirm");

      // Pure helpers.
      assert.equal(plugins["oob"].extractToken("a.b.c", ["b"]), "b");
      assert.equal(plugins["oob"].extractToken("nope", ["b"]), null);
      assert.equal(plugins["oob"].parseDnsQuestion(pkt), dnsMint.dnsName);
    } finally {
      // Do not assert inside finally: a throw here would replace the real error.
      stopped = JSON.parse(await tools.get("oob_stop").execute({}));
    }
    assert.equal(stopped.stopped, true);
    assert.ok(stopped.interactions >= 2, `stop summary counts interactions (got ${stopped.interactions})`);
  });

  // ------------------------------------------------------------ validators
  await test("validators decide per-class proof conditions", async () => {
    const { decideTiming, decideBoolean, decideRedirect, normalizeBody } = plugins["validators"];

    // Timing: a real injected delay confirms; ordinary jitter does not.
    const slow = decideTiming([{ ms: 100 }, { ms: 110 }, { ms: 105 }], [{ ms: 5200 }, { ms: 5150 }, { ms: 5300 }], 5000);
    assert.equal(slow.validated, true);
    assert.equal(slow.confidence, "high");
    const jitter = decideTiming([{ ms: 100 }, { ms: 110 }], [{ ms: 130 }, { ms: 120 }], 5000);
    assert.equal(jitter.validated, false, "jitter must not validate as blind SQLi");

    // Boolean: TRUE must match baseline AND FALSE must differ.
    assert.equal(
      decideBoolean({ status: 200, body: "welcome alice" }, { status: 200, body: "welcome alice" }, { status: 200, body: "no user" }).validated,
      true
    );
    assert.equal(
      decideBoolean({ status: 200, body: "a" }, { status: 200, body: "b" }, { status: 200, body: "c" }).validated,
      false,
      "TRUE not matching baseline is an uncontrolled comparison"
    );
    assert.equal(
      decideBoolean({ status: 200, body: "a" }, { status: 200, body: "a" }, { status: 200, body: "a" }).validated,
      false,
      "identical responses are not a signal"
    );

    // Redirect: server-side off-origin only.
    assert.equal(decideRedirect("https://evil.example/", ["target.com"], 302).validated, true);
    assert.equal(decideRedirect("//evil.example/", ["target.com"], 302).validated, true);
    assert.equal(decideRedirect("https://target.com/home", ["target.com"], 302).validated, false);
    assert.equal(decideRedirect("https://evil.example/", ["target.com"], 200).validated, false);
    assert.equal(decideRedirect("", ["target.com"], 302).validated, false);

    // Noise normalisation makes timestamps/ids comparable.
    assert.equal(
      normalizeBody("t=2026-01-01T00:00:00Z id=abc123def4567890"),
      normalizeBody("t=2027-02-02T11:11:11Z id=ffff9999aaaa0000")
    );

    // End-to-end against a loopback server that really redirects off-origin.
    const srv = createServer((_req, res) => {
      res.writeHead(302, { Location: "https://evil.example/" });
      res.end();
    });
    await new Promise((r) => srv.listen(0, "127.0.0.1", r));
    const port = srv.address().port;
    try {
      const { ctx, tools } = makeCtx({});
      plugins["validators"].apply(ctx);
      const vr = JSON.parse(
        await tools.get("validate_redirect").execute({
          url: `http://127.0.0.1:${port}/go`,
          allowedHosts: "target.com",
        })
      );
      assert.equal(vr.validated, true, "live loopback redirect confirmed");
      // OOB validator refuses to confirm without an interaction.
      const noOob = JSON.parse(
        await tools.get("validate_oob").execute({ token: "abc", interactions: "[]" })
      );
      assert.equal(noOob.validated, false);

      // Class router: dispatches each class to its real proof condition.
      const router = tools.get("validate_by_class");
      assert.ok(router, "validate_by_class registered");

      const idorRoute = JSON.parse(await router.execute({ bugClass: "idor", spec: "{}" }));
      assert.equal(idorRoute.route, "manual", "IDOR must not pretend to be payload-provable");
      assert.ok(/two identities/.test(idorRoute.reason));

      const redRoute = JSON.parse(
        await router.execute({
          bugClass: "open-redirect",
          spec: JSON.stringify({ url: `http://127.0.0.1:${port}/go`, allowedHosts: "target.com" }),
        })
      );
      assert.equal(redRoute.route, "validate_redirect");
      assert.equal(redRoute.validated, true, "router executes the redirect validator");

      const sqliRoute = JSON.parse(
        await router.execute({ bugClass: "blind-sqli", spec: JSON.stringify({ baselineUrl: "http://x" }) })
      );
      assert.equal(sqliRoute.validated, false);
      assert.ok(/baselineUrl/.test(sqliRoute.error || ""), "missing spec fields are reported");

      const unknown = JSON.parse(await router.execute({ bugClass: "not-a-real-class", spec: "{}" }));
      assert.ok(unknown.error, "unknown class is refused, not silently passed");
    } finally {
      await new Promise((r) => srv.close(r));
    }
  });

  // ---------------------------------------------------------- asset-dedup
  await test("dedup_assets clusters clones and separates genuinely different pages", async () => {
    const { simhash, hamming, clusterBySimhash, dedup_assets } = plugins["asset-dedup"];
    void dedup_assets;
    const page =
      "<html><body><h1>Acme Portal</h1><p>Welcome to the portal. Please sign in to continue to your dashboard.</p></body></html>";
    const clone = page.replace("Acme", "Acme").replace("portal", "portal") + "<!-- build 42 -->";
    const different =
      "<html><body><h1>Totally Different Shop</h1><p>Buy shoes, hats and coats in our online store today.</p></body></html>";

    assert.ok(hamming(simhash(page), simhash(clone)) <= 6, "near-identical pages must be close");
    assert.ok(hamming(simhash(page), simhash(different)) > 6, "unrelated pages must be far apart");

    const clusters = clusterBySimhash(
      [
        { id: "a.example.test", text: page },
        { id: "stage0001-dev.example.test", text: clone },
        { id: "other.example.test", text: different },
      ],
      6
    );
    assert.equal(clusters.length, 2, "clone collapses into the representative's cluster");
    const big = clusters.find((c) => c.size === 2);
    assert.ok(big, "a 2-member cluster exists");
    assert.equal(big.representative, "a.example.test");

    // Tool surface: inline items path.
    const { ctx, tools } = makeCtx({});
    plugins["asset-dedup"].apply(ctx);
    const res = JSON.parse(
      await tools.get("dedup_assets").execute({
        items: JSON.stringify([
          { id: "x", text: page },
          { id: "y", text: clone },
        ]),
      })
    );
    assert.equal(res.clusters, 1);
    assert.equal(res.duplicate_assets, 1);
  });

  // ------------------------------------------------------ browser-validate
  await test("validate_xss_browser confirms execution only when the payload actually runs", async () => {
    // Serve one page that executes and one that merely reflects.
    const srv = createServer((req, res) => {
      res.writeHead(200, { "Content-Type": "text/html" });
      if ((req.url || "").startsWith("/exec")) {
        res.end(`<html><body><img src=x onerror="window.__bh_xss=1"></body></html>`);
      } else {
        res.end(`<html><body><p>&lt;img src=x onerror=alert(1)&gt;</p></body></html>`);
      }
    });
    await new Promise((r) => srv.listen(0, "127.0.0.1", r));
    const port = srv.address().port;
    try {
      const { ctx, tools } = makeCtx({});
      plugins["browser-validate"].apply(ctx);
      const tool = tools.get("validate_xss_browser");

      const exec = JSON.parse(await tool.execute({ url: `http://127.0.0.1:${port}/exec`, settleMs: 600 }));
      if (exec.available === false) {
        // Must fail LOUDLY, never quietly report "not vulnerable".
        assert.ok(/playwright/i.test(exec.error + exec.note), "unavailable must name playwright");
        console.log("      (skipped execution assertions: chromium not installed)");
      } else {
        assert.equal(exec.executed, true, "executing payload must be confirmed");
        const safe = JSON.parse(await tool.execute({ url: `http://127.0.0.1:${port}/safe`, settleMs: 600 }));
        assert.equal(safe.executed, false, "escaped payload must NOT be confirmed as XSS");
      }
    } finally {
      await new Promise((r) => srv.close(r));
    }
  });

  // ------------------------------------------------------------ skill-rag
  await test("retrieve_skills ranks by meaning, not only literal keyword overlap", async () => {
    const { buildIndex, rank } = plugins["skill-rag"];
    const docs = [
      { id: "seeds/lfi", path: "lfi.md", text: "path traversal local file inclusion directory traversal ../../etc/passwd file parameter resolved on disk" },
      { id: "seeds/cors", path: "cors.md", text: "cross origin resource sharing access-control-allow-origin credentials reflection" },
      { id: "seeds/xss", path: "xss.md", text: "cross-site scripting reflected stored dom innerHTML script execution" },
    ];
    const idx = buildIndex(docs);

    // Paraphrase: none of these words appear verbatim in several docs at once.
    const r1 = rank(idx, "an endpoint takes a file name and resolves it on the filesystem", 2);
    assert.equal(r1[0].id, "seeds/lfi", "paraphrased file-read query must surface LFI");

    const r2 = rank(idx, "the browser executed my script tag", 2);
    assert.equal(r2[0].id, "seeds/xss");

    const r3 = rank(idx, "zzzz-nonexistent-term", 3);
    assert.equal(r3.length, 0, "no overlap yields no candidates");

    // Tool surface over the real skill library.
    const { ctx, tools } = makeCtx({});
    plugins["skill-rag"].apply(ctx);
    const res = JSON.parse(
      await tools.get("retrieve_skills").execute({ query: "insecure direct object reference changing an id", k: 5 })
    );
    assert.ok(res.indexed_skills > 10, `expected the real skill library to be indexed (got ${res.indexed_skills})`);
    assert.ok(res.candidates.length > 0);
  });

  // ----------------------------------------------------------------- eval
  await test("eval harness runs the fixture and scores detection precisely", async () => {
    const { score, canonicalClass } = plugins["eval"];
    const truth = JSON.parse(await readFile(join(ROOT, "plugins/dsh-eval/ground-truth.json"), "utf8"));

    assert.equal(canonicalClass("Broken Authorization", truth.class_aliases), "idor");
    assert.equal(canonicalClass("Reflected XSS", truth.class_aliases), "xss");

    // Perfect run.
    const perfect = score(
      truth.bugs.map((b) => ({ class: b.class, path: b.path })),
      truth
    );
    assert.equal(perfect.tp, truth.bugs.length);
    assert.equal(perfect.fp, 0);
    assert.equal(perfect.fn, 0);
    assert.equal(perfect.precision, 1);
    assert.equal(perfect.recall, 1);

    // Partial run with one false positive.
    const partial = score(
      [
        { class: "idor", path: "/api/users/2" },
        { class: "xss", path: "/search?q=x" },
        { class: "made-up-class", path: "/nothing" },
      ],
      truth
    );
    assert.equal(partial.tp, 2);
    assert.equal(partial.fp, 1, "unmatched finding is a false positive");
    assert.equal(partial.fn, truth.bugs.length - 2, "unfound planted bugs are false negatives");
    assert.ok(partial.precision < 1 && partial.recall < 1);

    // Live fixture: start it, probe it, confirm a real bug, score it.
    const { ctx, tools } = makeCtx({});
    plugins["eval"].apply(ctx);
    const port = 8300 + Math.floor(Math.random() * 300);
    const started = JSON.parse(await tools.get("eval_start_fixture").execute({ port }));
    assert.equal(started.started, true, "fixture starts");
    assert.equal(started.bound, "127.0.0.1", "fixture must bind loopback only");
    try {
      const idor = await fetch(`${started.url}/api/users/2`);
      const body = await idor.json();
      assert.equal(body.name, "bob", "fixture IDOR really leaks another user");
      const redirect = await fetch(`${started.url}/go?next=https://evil.example/`, { redirect: "manual" });
      assert.equal(redirect.status, 302);
      assert.equal(redirect.headers.get("location"), "https://evil.example/", "fixture open redirect really fires");

      const scored = JSON.parse(
        await tools.get("eval_score").execute({
          findings: JSON.stringify([
            { class: "idor", path: "/api/users/{id}" },
            { class: "open-redirect", path: "/go?next=" },
          ]),
        })
      );
      assert.equal(scored.tp, 2);
      assert.equal(scored.planted, truth.bugs.length);
    } finally {
      await tools.get("eval_stop_fixture").execute({});
    }
  });

  // -------------------------------------------------------- scope-intake
  await test("parse_program_scope extracts scope, exclusions and policy flags", async () => {
    const { parseProgramText, sectionize } = plugins["scope-intake"];
    const text = [
      "In scope:",
      "*.example.com",
      "api.example.com",
      "",
      "Out of scope:",
      "status.example.com",
      "third-party.example.com",
      "",
      "Rules: Do not run automated scanners against production.",
      "Denial of service and brute force attacks are prohibited.",
      "Reports about missing security headers are not accepted.",
      "Cache poisoning is excluded from this program.",
    ].join("\n");

    const p = parseProgramText(text);
    assert.ok(p.in_scope.includes("api.example.com"), "explicit host in scope");
    assert.ok(p.in_scope.includes("*.example.com"), "wildcard captured");
    assert.ok(p.out_of_scope.includes("status.example.com"), "exclusion captured");
    assert.ok(!p.in_scope.includes("status.example.com"), "excluded host removed from in_scope");

    const flagIds = p.policy_flags.map((f) => f.id);
    assert.ok(flagIds.includes("automated-scanning"), "automated scanning rule detected");
    assert.ok(flagIds.includes("dos"), "DoS rule detected");
    assert.ok(flagIds.includes("brute-force"), "brute force rule detected");
    assert.ok(flagIds.includes("cache-poisoning"), "cache poisoning exclusion detected");
    assert.ok(p.excluded_classes.includes("cache-poisoning"), "excluded class surfaced for triage_gate");

    assert.ok(sectionize(text).some((s) => s.mode === "out"), "sections are tracked");

    // Integration: an excluded class must fail the gate.
    const gatePlugin = plugins["triage-gate"];
    const yes = {
      q1Reproducible: true, q2ImpactAccepted: true, q3InScope: true,
      q4NoPrivilegedAccess: true, q5NotKnown: true, q6ProvenImpact: true, q7NotAlwaysRejected: true,
    };
    const killed = gatePlugin.runGate({
      title: "Cache poisoning on the CDN edge allows stored XSS",
      impact: "stored XSS for all users",
      answers: yes,
      programExclusions: p.excluded_classes,
    });
    assert.equal(killed.passed, false, "program-excluded class must fail the gate");
    assert.ok(killed.failures.some((f) => f.includes("policy excludes")));
  });

  // ------------------------------------------------- coverage: 2 identities
  await test("coverage refuses to mark a cross-identity class tested from one account", async () => {
    const huntsRoot = await mkdtemp(join(tmpdir(), "bh-cov2-"));
    await mkdir(join(huntsRoot, "example.test"), { recursive: true });
    await writeFile(join(huntsRoot, "example.test", "scope.txt"), "app.example.test\n");
    const { ctx, tools } = makeCtx({});
    plugins["coverage"].apply(ctx, { huntsRoot, skillsRoot: join(ROOT, "skills") });
    await tools.get("coverage_init").execute({ domain: "example.test", classes: "idor,sqli" });

    // One identity is not enough for IDOR.
    const refused = JSON.parse(
      await tools.get("coverage_mark").execute({
        domain: "example.test", vulnClass: "idor", asset: "app.example.test", status: "tested", identities: 1,
      })
    );
    assert.equal(refused.marked, false, "IDOR with 1 identity must be refused");
    assert.ok(/identities/.test(refused.error));

    // Two identities is fine.
    const ok = JSON.parse(
      await tools.get("coverage_mark").execute({
        domain: "example.test", vulnClass: "idor", asset: "app.example.test", status: "tested", identities: 2,
      })
    );
    assert.equal(ok.marked, true);

    // A single-identity class is unaffected.
    const sqli = JSON.parse(
      await tools.get("coverage_mark").execute({
        domain: "example.test", vulnClass: "sqli", asset: "app.example.test", status: "tested",
      })
    );
    assert.equal(sqli.marked, true, "sqli does not require two identities");

    // Marking it blocked-with-reason is the honest alternative and still resolves the cell.
    const blocked = JSON.parse(
      await tools.get("coverage_mark").execute({
        domain: "example.test", vulnClass: "idor", asset: "other.test", status: "blocked",
        reason: "no second account/tenant available",
      })
    );
    assert.equal(blocked.marked, true);
  });

  // ------------------------------------------------------------- live proxy
  await test("proxy captures plain HTTP and HTTPS CONNECT from any client", async () => {
    const upstreamPort = 8910 + Math.floor(Math.random() * 60);
    const proxyPort = 9010 + Math.floor(Math.random() * 60);

    const upstream = createServer((req, res) => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(`upstream:${req.url}`);
    });
    await new Promise((r) => upstream.listen(upstreamPort, "127.0.0.1", r));

    const captureLog = join(await mkdtemp(join(tmpdir(), "bh-proxy-")), "capture.jsonl");
    const { ctx, tools } = makeCtx({});
    plugins["proxy"].apply(ctx, { port: proxyPort, bindHost: "127.0.0.1", logPath: captureLog, mitm: false });
    const started = JSON.parse(await tools.get("proxy_start").execute({}));
    assert.equal(started.started, true, "proxy starts");

    try {
      // Plain HTTP through the proxy: absolute-form request URI.
      const viaProxy = await new Promise((resolve, reject) => {
        const r = http.request(
          {
            host: "127.0.0.1",
            port: proxyPort,
            method: "GET",
            path: `http://127.0.0.1:${upstreamPort}/proxied?x=1`,
            headers: { Host: `127.0.0.1:${upstreamPort}` },
          },
          (res) => {
            const c = [];
            res.on("data", (d) => c.push(d));
            res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(c).toString() }));
          }
        );
        r.on("error", reject);
        r.end();
      });
      assert.equal(viaProxy.status, 200);
      assert.ok(viaProxy.body.includes("/proxied?x=1"), "response is proxied through");

      // HTTPS via CONNECT: the tunnel target must be recorded.
      await new Promise((resolve) => {
        const r = http.request({ host: "127.0.0.1", port: proxyPort, method: "CONNECT", path: "example.test:443" });
        r.on("connect", () => {
          r.destroy();
          resolve();
        });
        r.on("error", () => resolve());
        r.end();
      });

      const caps = JSON.parse(await tools.get("proxy_requests").execute({ limit: 20 }));
      assert.ok(caps.total >= 2, `expected at least 2 captures, got ${caps.total}`);
      const httpCap = caps.requests.find((c) => c.scheme === "http");
      assert.ok(httpCap, "plain HTTP captured");
      assert.ok(String(httpCap.url).includes("/proxied?x=1"), "captured the full path and query");
      const connectCap = caps.requests.find((c) => c.method === "CONNECT");
      assert.ok(connectCap, "HTTPS CONNECT captured");
      assert.equal(connectCap.host, "example.test");
    } finally {
      await tools.get("proxy_stop").execute({});
      await new Promise((r) => upstream.close(r));
    }
  });

  // ------------------------------------------------- perceptual image hash
  await test("perceptual hashing groups visually identical pages and separates others", async () => {
    const { clusterByHashes, hammingHex } = plugins["asset-dedup"];
    const nav = '<header style="background:#123;color:#fff;padding:20px"><b>ACME</b> <a>Home</a> <a>Docs</a></header>';
    const A = `<html><body style="margin:0;font-family:sans-serif">${nav}<main style="padding:30px"><h1>Acme Portal</h1><p>Sign in to continue to your dashboard.</p><input><button>Login</button><ul><li>One</li><li>Two</li></ul></main></body></html>`;
    const A2 = A.replace("Sign in", "Please sign in");
    const B = '<html><body style="margin:0;background:#111;color:#0f0;font-family:monospace"><h1>ZZZ UNRELATED</h1><table><tr><td>a</td><td>b</td></tr></table><p>different layout entirely</p></body></html>';

    const srv = createServer((req, res) => {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end((req.url || "").startsWith("/b") ? B : (req.url || "").startsWith("/a2") ? A2 : A);
    });
    await new Promise((r) => srv.listen(0, "127.0.0.1", r));
    const port = srv.address().port;
    try {
      const { ctx, tools } = makeCtx({});
      plugins["browser-validate"].apply(ctx);
      const res = JSON.parse(
        await tools.get("hash_screenshots").execute({
          urls: [`http://127.0.0.1:${port}/a`, `http://127.0.0.1:${port}/a2`, `http://127.0.0.1:${port}/b`].join("\n"),
          settleMs: 300,
        })
      );
      if (res.available === false || res.hashed === 0) {
        console.log("      (skipped: chromium not installed)");
        return;
      }
      const imgs = res.images.filter((i) => i.dhash);
      assert.equal(imgs.length, 3, "all three screenshots hashed");
      const near = hammingHex(imgs[0].dhash, imgs[1].dhash);
      const far = hammingHex(imgs[0].dhash, imgs[2].dhash);
      assert.ok(near < far, `similar pages must be closer than unrelated ones (${near} vs ${far})`);
      const clusters = clusterByHashes(imgs, 8);
      assert.equal(clusters.length, 2, "clones collapse, the unrelated page stands alone");
      assert.ok(clusters.some((c) => c.size === 2), "the clone pair forms a 2-member cluster");
    } finally {
      await new Promise((r) => srv.close(r));
    }
  });

  // --------------------------------------------------- concept-expanded RAG
  await test("skill retrieval matches synonyms, not just literal keywords", async () => {
    const { expandQuery, matchedConcepts, CONCEPTS } = plugins["skill-rag"];

    // None of these contain the string "ssrf", which is exactly the failure mode.
    for (const phrase of ["server fetches a URL", "url parameter fetch", "callback url"]) {
      assert.ok(matchedConcepts(`target has a ${phrase}`).includes("ssrf"), `${phrase} -> ssrf`);
    }
    const expanded = expandQuery("the endpoint makes the server fetches a URL");
    assert.ok(expanded.query.toLowerCase().includes("ssrf"), "expansion injects the canonical term");
    assert.ok(Object.keys(CONCEPTS).length >= 15, "thesaurus covers the main classes");

    const { ctx, tools } = makeCtx({});
    plugins["skill-rag"].apply(ctx);
    const r = JSON.parse(
      await tools.get("retrieve_skills").execute({ query: "server fetches a URL from a parameter", k: 3 })
    );
    assert.ok(r.matched_concepts.includes("ssrf"));
    assert.ok(
      r.candidates.some((c) => c.id.includes("ssrf")),
      `ssrf skill must be retrieved; got ${r.candidates.map((c) => c.id).join(", ")}`
    );
    // Embeddings are optional: must report status, never throw.
    assert.ok(typeof r.embeddings === "string" && r.embeddings.length > 0);
  });

  // ---------------------------------------------------------------- summary
  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} passed`);
  if (failed.length > 0) {
    console.log(`failed: ${failed.map((f) => f.name).join(" | ")}`);
    process.exitCode = 1;
  }
}

await main();
