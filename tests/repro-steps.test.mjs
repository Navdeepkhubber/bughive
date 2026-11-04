import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { REPRO_STATES, isReproState, parseSteps } from "../plugins/dsh-repro-steps/parse.js";
import { runAuthoredSteps } from "../plugins/dsh-repro-steps/run.js";
import { apply as skillLoader } from "../plugins/dsh-skill-loader/index.js";
import { apply as validators } from "../plugins/dsh-validators/index.js";
import { buildExecutor } from "../scripts/pipeline/jev-decide.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function startFixture() {
  const hits = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      hits.push({ method: req.method, url: req.url, body, xLab: req.headers["x-lab"] || "", contentType: req.headers["content-type"] || "" });
      if (req.url.startsWith("/export")) {
        res.writeHead(200, { "content-type": "text/plain", "x-lab": req.headers["x-lab"] || "" });
        res.end("root:x:0:0:root:/root:/bin/bash\n");
        return;
      }
      if (req.url.startsWith("/waf")) {
        res.writeHead(200, { "content-type": "text/html" });
        res.end("<html>Attention Required root:x:</html>");
        return;
      }
      if (req.url.startsWith("/miss")) {
        res.writeHead(404, { "content-type": "text/plain" });
        res.end("nope");
        return;
      }
      if (req.url.startsWith("/echo")) {
        res.writeHead(200, {
          "content-type": "text/plain",
          "x-lab": req.headers["x-lab"] || "",
        });
        res.end(body);
        return;
      }
      if (req.url.startsWith("/health")) {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("ok");
        return;
      }
      if (req.url.startsWith("/empty")) {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("hello");
        return;
      }
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("missing");
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      resolve({
        hits,
        baseUrl: `http://127.0.0.1:${port}`,
        scope: "127.0.0.1",
        close: () => new Promise((done) => server.close(done)),
      });
    });
  });
}

function spyFetch() {
  const calls = [];
  return {
    calls,
    fetchImpl: async (url) => {
      calls.push(url);
      throw new Error(`fetch attempted for ${url}`);
    },
  };
}

const DOC_ONLY = `## Steps to reproduce

> Status: \`repro: verified-public\` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: example app < 1.2. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-0001)]

### Input / trigger
- NVD characterizes the trigger as information disclosure. No concrete request string from the advisory was copied.

### How to confirm
- Against a disposable lab build, compare it with a patched build. A 200 response is not sufficient.

### What's missing
- (none for verified-public)
`;

const OUTSIDE_FENCE = `## Probe
\`\`\`http
GET /should-not-run HTTP/1.1
Host: example.com
\`\`\`

${DOC_ONLY}`;

test("parser reads only authored steps and does not invent a request or assertion", () => {
  const outside = parseSteps(OUTSIDE_FENCE);
  assert.equal(outside.present, true);
  assert.equal(outside.runnable, false);
  assert.equal(outside.blocks.length, 1);
  assert.equal(outside.blocks[0].repro, "verified-public");
  assert.deepEqual(outside.blocks[0].requests, []);
  assert.equal(outside.blocks[0].success.checks.length, 0);
  assert.equal(outside.blocks[0].preconditions[0].includes("example app < 1.2"), true);
  assert.equal(outside.blocks[0].preconditions[0].includes("[[nvd]"), true);
  assert.equal(outside.blocks[0].reason, "no authored HTTP request");

  const empty = parseSteps("# no steps here\nGET /invented\n");
  assert.equal(empty.present, false);
  assert.equal(empty.runnable, false);
  assert.deepEqual(empty.blocks, []);
});

test("parser keeps a machine-checkable request, success condition, and false-positive guard", () => {
  const parsed = parseSteps(`## Steps to reproduce — lab export

### Preconditions
- In-scope lab host

### Steps
1. POST /echo
   header Content-Type: application/x-www-form-urlencoded
   header X-Lab: authored-header
   body: marker=authored-body
2. GET /export?file=../../etc/passwd

### Success condition
- step 1 status: 200
- step 1 body contains: marker=authored-body
- step 2 body contains: "root:x:"
- step 2 header X-Lab equals authored-header

### False-positive guard
- body contains: Attention Required
`);
  assert.equal(parsed.runnable, true);
  assert.equal(parsed.blocks[0].title, "lab export");
  assert.deepEqual(parsed.blocks[0].preconditions, ["In-scope lab host"]);
  assert.equal(parsed.blocks[0].requests.length, 2);
  assert.equal(parsed.blocks[0].requests[0].method, "POST");
  assert.equal(parsed.blocks[0].requests[0].path, "/echo");
  assert.equal(parsed.blocks[0].requests[0].body, "marker=authored-body");
  assert.deepEqual(parsed.blocks[0].requests[0].headers, {
    "Content-Type": "application/x-www-form-urlencoded",
    "X-Lab": "authored-header",
  });
  assert.equal(parsed.blocks[0].requests[1].method, "GET");
  assert.equal(parsed.blocks[0].requests[1].step, 2);
  assert.equal(parsed.blocks[0].requests[1].body, undefined);
  const checks = parsed.blocks[0].success.checks;
  assert.equal(checks[0].kind, "status");
  assert.equal(checks[0].value, 200);
  assert.equal(checks[0].step, 1);
  assert.equal(checks[2].kind, "body_contains");
  assert.equal(checks[2].value, "root:x:");
  assert.equal(parsed.blocks[0].falsePositiveGuard.checks[0].kind, "body_contains");
  assert.equal(parsed.blocks[0].falsePositiveGuard.checks[0].value, "Attention Required");
});

test("parser accepts an authored http fence and refuses prose that is not a check", () => {
  const fenced = parseSteps(`## Steps to reproduce
### Requests
\`\`\`http
POST /echo HTTP/1.1
X-Lab: fence

marker=from-fence
\`\`\`
### Success condition
- status: 200
- body contains: marker=from-fence
- regex: marker=from-fence
`);
  assert.equal(fenced.runnable, true);
  assert.equal(fenced.blocks[0].requests[0].method, "POST");
  assert.equal(fenced.blocks[0].requests[0].path, "/echo");
  assert.equal(fenced.blocks[0].requests[0].headers["X-Lab"], "fence");
  assert.equal(fenced.blocks[0].requests[0].body, "marker=from-fence");
  assert.equal(fenced.blocks[0].success.checks.some((check) => check.kind === "regex" && check.value === "marker=from-fence"), true);

  const proseStep = parseSteps(`## Steps to reproduce
### Steps
1. Log in as the lab user
2. GET /export
### Success condition
- status: 200
`);
  assert.equal(proseStep.runnable, false);
  assert.equal(proseStep.blocks[0].reason, "a step is not an HTTP request");
  assert.equal(proseStep.blocks[0].requests.length, 1);

  const proseSuccess = parseSteps(`## Steps to reproduce
### Steps
1. GET /export
### How to confirm
- Look for signs of file disclosure.
`);
  assert.equal(proseSuccess.runnable, false);
  assert.equal(proseSuccess.blocks[0].reason, "success condition is not machine-checkable");

  const proseGuard = parseSteps(`## Steps to reproduce
### Steps
1. GET /export
### Success condition
- status: 200
### False-positive guard
- Ignore vendor marketing pages.
`);
  assert.equal(proseGuard.runnable, false);
  assert.equal(proseGuard.blocks[0].reason, "false-positive guard is not machine-checkable");

  const gap = parseSteps(`## Steps to reproduce
### Steps
1. GET /export
### Success condition
- status: 200
### What's missing
- No concrete request or payload in the cited advisories. None was invented.
`);
  assert.equal(gap.runnable, false);
  assert.equal(gap.blocks[0].reason, "authored gap in What's missing");
});

test("runner confirms, rejects, and stays inconclusive only from authored steps", async () => {
  const fx = await startFixture();
  const calls = spyFetch();
  try {
    const doc = await runAuthoredSteps(DOC_ONLY, {
      baseUrl: fx.baseUrl,
      scope: fx.scope,
      fetchImpl: calls.fetchImpl,
    });
    assert.equal(doc.result, "inconclusive");
    assert.equal(doc.runnable, false);
    assert.equal(doc.evidence.executed, false);
    assert.equal(calls.calls.length, 0);
    assert.equal(fx.hits.length, 0);

    const confirmed = await runAuthoredSteps(`## Steps to reproduce
### Steps
1. GET {{BaseURL}}/export?file=../../etc/passwd
### Success condition
- status: 200
- body contains: root:x:
### False-positive guard
- body contains: Attention Required
`, { baseUrl: fx.baseUrl, scope: fx.scope });
    assert.equal(confirmed.result, "confirmed");
    assert.equal(confirmed.evidence.executed, true);
    assert.equal(confirmed.evidence.observations[0].status, 200);
    assert.equal(confirmed.evidence.observations[0].url, `${fx.baseUrl}/export?file=../../etc/passwd`);
    assert.equal(confirmed.evidence.success.every((check) => check.passed), true);
    assert.equal(confirmed.evidence.falsePositiveGuard[0].tripped, false);
    assert.equal(fx.hits.at(-1).url, "/export?file=../../etc/passwd");

    const missed = await runAuthoredSteps(`## Steps to reproduce
### Steps
1. GET /miss
### Success condition
- status: 200
- body contains: root:x:
`, { baseUrl: fx.baseUrl, scope: fx.scope });
    assert.equal(missed.result, "not-confirmed");
    assert.equal(missed.reason, "authored success condition did not hold");
    assert.equal(missed.evidence.success.some((check) => check.passed === false), true);

    const fp = await runAuthoredSteps(`## Steps to reproduce
### Steps
1. GET /waf
### Success condition
- status: 200
- body contains: root:x:
### False-positive guard
- body contains: Attention Required
`, { baseUrl: fx.baseUrl, scope: fx.scope });
    assert.equal(fp.result, "not-confirmed");
    assert.equal(fp.reason, "false-positive guard matched");
    assert.equal(fp.evidence.falsePositiveGuard[0].tripped, true);

    const negative = await runAuthoredSteps(`## Steps to reproduce
### Steps
1. GET /empty
### Success condition
- status: 200
- body does not contain: root:x:
`, { baseUrl: fx.baseUrl, scope: fx.scope });
    assert.equal(negative.result, "confirmed");

    const before = fx.hits.length;
    const unresolved = await runAuthoredSteps(`## Steps to reproduce
### Steps
1. GET /item?id={{payload}}
### Success condition
- status: 200
`, { baseUrl: fx.baseUrl, scope: fx.scope, fetchImpl: calls.fetchImpl });
    assert.equal(unresolved.result, "inconclusive");
    assert.match(unresolved.reason, /placeholder/);
    assert.equal(fx.hits.length, before);
    assert.equal(calls.calls.length, 0);

    const noBase = await runAuthoredSteps(`## Steps to reproduce
### Steps
1. GET /export
### Success condition
- status: 200
`, { scope: fx.scope, fetchImpl: calls.fetchImpl });
    assert.equal(noBase.result, "inconclusive");
    assert.match(noBase.reason, /base URL/);
    assert.equal(calls.calls.length, 0);

    const offScope = await runAuthoredSteps(`## Steps to reproduce
### Steps
1. GET http://example.com/secret
### Success condition
- status: 200
`, { baseUrl: fx.baseUrl, scope: fx.scope, fetchImpl: calls.fetchImpl });
    assert.equal(offScope.result, "inconclusive");
    assert.equal(offScope.reason, "out of scope");
    assert.equal(calls.calls.length, 0);

    const posted = await runAuthoredSteps(`## Steps to reproduce
### Steps
1. POST /echo
   header Content-Type: application/x-www-form-urlencoded
   header X-Lab: authored-header
   body: marker=authored-body
### Success condition
- status: 200
- body contains: marker=authored-body
- header X-Lab equals authored-header
`, { baseUrl: fx.baseUrl, scope: fx.scope });
    assert.equal(posted.result, "confirmed");
    const echo = fx.hits.find((hit) => hit.url === "/echo");
    assert.equal(echo.method, "POST");
    assert.equal(echo.body, "marker=authored-body");
    assert.equal(echo.xLab, "authored-header");
    assert.equal(echo.contentType.includes("application/json"), false);

    const stepped = await runAuthoredSteps(`## Steps to reproduce
### Steps
1. GET /health
2. GET /export
### Success condition
- step 1 status: 200
- step 1 body contains: ok
- step 2 body contains: root:x:
`, { baseUrl: fx.baseUrl, scope: fx.scope });
    assert.equal(stepped.result, "confirmed");
    assert.deepEqual(stepped.evidence.observations.map((obs) => obs.url), [
      `${fx.baseUrl}/health`,
      `${fx.baseUrl}/export`,
    ]);

    const absolute = await runAuthoredSteps(`## Steps to reproduce
### Steps
1. GET ${fx.baseUrl}/health
### Success condition
- body contains: ok
`, { scope: fx.scope });
    assert.equal(absolute.result, "confirmed");
  } finally {
    await fx.close();
  }
});

test("a real enrich-repro skill stays inconclusive and is not executed", async () => {
  const text = await readFile(join(ROOT, "skills/seeds/apache-struts.md"), "utf8");
  const parsed = parseSteps(text);
  assert.equal(parsed.present, true);
  assert.equal(parsed.runnable, false);
  for (const block of parsed.blocks) {
    assert.equal(block.requests.length, 0);
    assert.equal(block.success.checks.length, 0);
    assert.equal(block.runnable, false);
  }
  const calls = spyFetch();
  const outcome = await runAuthoredSteps(parsed, {
    baseUrl: "http://127.0.0.1:9",
    scope: "127.0.0.1",
    fetchImpl: calls.fetchImpl,
  });
  assert.equal(outcome.result, "inconclusive");
  assert.equal(outcome.evidence.executed, false);
  assert.equal(calls.calls.length, 0);
});

test("loader carries parsed steps and accepts technique-authored", async () => {
  assert.deepEqual(REPRO_STATES, [
    "verified-public",
    "partial",
    "unverified",
    "checklist",
    "technique-authored",
  ]);
  assert.equal(isReproState("technique-authored"), true);
  assert.equal(isReproState("invented"), false);

  const root = await mkdtemp(join(tmpdir(), "bughive-steps-"));
  const seeds = join(root, "seeds");
  await mkdir(seeds);
  await writeFile(join(seeds, "export.md"), `---
repro: technique-authored
severity: high
---

# SKILL: lab export
Distinctive lab export traversal marker.

## Steps to reproduce

### Preconditions
- In-scope lab host

### Steps
1. GET /export?file=../../etc/passwd

### Success condition
- status: 200
- body contains: root:x:
`);
  await writeFile(join(seeds, "bad.md"), `---
repro: invented
---

Distinctive lab export traversal marker for an unknown repro state.
`);
  try {
    const tools = new Map();
    skillLoader({ tools: { register: (tool) => tools.set(tool.name, tool) } }, {
      skillsRoot: root,
      externalLearnedDir: join(root, "missing-learned"),
    });
    const loaded = JSON.parse(await tools.get("load_skills_for_target").execute({
      profile: "Distinctive lab export traversal",
    }));
    const skill = loaded.skills.find((item) => item.source === "seeds/export.md");
    const bad = loaded.skills.find((item) => item.source === "seeds/bad.md");
    assert.ok(skill, "technique-authored skill loaded");
    assert.equal(skill.repro, "technique-authored");
    assert.equal(skill.reproState, "technique-authored");
    assert.equal(skill.steps.runnable, true);
    assert.equal(skill.steps.blocks[0].requests[0].method, "GET");
    assert.equal(skill.steps.blocks[0].requests[0].path, "/export?file=../../etc/passwd");
    assert.equal(skill.steps.blocks[0].success.checks[1].kind, "body_contains");
    assert.equal(skill.steps.blocks[0].success.checks[1].value, "root:x:");
    assert.ok(bad);
    assert.equal(bad.repro, "invented");
    assert.equal(bad.reproState, null);
    assert.equal(bad.steps.present, false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("prove gate confirms authored steps by execution and does not promote a miss", async () => {
  const exec = buildExecutor({ next_action: "prove" }, "app.example");
  assert.equal(exec.plugin, "validate_by_class");
  assert.equal(exec.repro_route, "execute_repro");
  assert.match(exec.plugin_note, /execute_repro/);
  assert.match(exec.plugin_note, /inconclusive/);

  const fx = await startFixture();
  try {
    const tools = new Map();
    validators({ tools: { register: (tool) => tools.set(tool.name, tool) } });
    const router = tools.get("validate_by_class");
    const confirmed = JSON.parse(await router.execute({
      bugClass: "lfi",
      spec: JSON.stringify({
        baseUrl: fx.baseUrl,
        scope: fx.scope,
        skillMarkdown: `## Steps to reproduce
### Steps
1. GET /export?file=../../etc/passwd
### Success condition
- status: 200
- body contains: root:x:
### False-positive guard
- body contains: Attention Required
`,
      }),
    }));
    assert.equal(confirmed.route, "execute_repro");
    assert.equal(confirmed.result, "confirmed");
    assert.equal(confirmed.validated, true);
    assert.equal(confirmed.evidence.observations[0].status, 200);

    const missed = JSON.parse(await router.execute({
      bugClass: "open-redirect",
      spec: JSON.stringify({
        baseUrl: fx.baseUrl,
        scope: fx.scope,
        url: `${fx.baseUrl}/go`,
        allowedHosts: "target.com",
        skillMarkdown: `## Steps to reproduce
### Steps
1. GET /miss
### Success condition
- status: 200
- body contains: root:x:
`,
      }),
    }));
    assert.equal(missed.route, "execute_repro");
    assert.equal(missed.result, "not-confirmed");
    assert.equal(missed.validated, false);

    const doc = JSON.parse(await router.execute({
      bugClass: "not-a-real-class",
      spec: JSON.stringify({ skillMarkdown: DOC_ONLY, baseUrl: fx.baseUrl, scope: fx.scope }),
    }));
    assert.equal(doc.validated, false);
    assert.equal(doc.repro.result, "inconclusive");
    assert.equal(doc.repro.runnable, false);
    assert.notEqual(doc.result, "confirmed");
  } finally {
    await fx.close();
  }
});
