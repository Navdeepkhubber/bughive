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
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

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
  await test("all five plugin modules import and export {name, inject, apply}", async () => {
    for (const rel of [
      "plugins/dsh-recon-orchestrator/index.js",
      "plugins/dsh-finding-validator/index.js",
      "plugins/dsh-chain-builder/index.js",
      "plugins/dsh-report-writer/index.js",
      "plugins/dsh-skill-loader/index.js",
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
    assert.deepEqual(JSON.parse(value), {
      validated: false,
      diff: { statusChanged: false, lengthDelta: 0, bodyDiffers: false },
    });
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

  // ---------------------------------------------------------------- summary
  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} passed`);
  if (failed.length > 0) {
    console.log(`failed: ${failed.map((f) => f.name).join(" | ")}`);
    process.exitCode = 1;
  }
}

await main();
