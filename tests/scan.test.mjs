import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { runScan, writeScanOutput } from "../plugins/dsh-scan/index.js";
import { score } from "../plugins/dsh-eval/index.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE = join(ROOT, "plugins/dsh-eval/fixture-app.mjs");

function startFixture(port) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [FIXTURE, "--port", String(port)], { stdio: ["ignore", "pipe", "pipe"] });
    const timer = setTimeout(() => reject(new Error("fixture did not listen")), 8000);
    child.stdout.on("data", (buf) => {
      if (String(buf).includes("listening")) {
        clearTimeout(timer);
        resolve(child);
      }
    });
    child.on("exit", () => {
      clearTimeout(timer);
      reject(new Error("fixture exited"));
    });
  });
}

test("pinned rules confirm every planted fixture bug and none of the benign routes", async () => {
  const port = 18123;
  const child = await startFixture(port);
  try {
    const result = await runScan({
      base: `http://127.0.0.1:${port}`,
      scopeText: "127.0.0.1",
      skillsDir: join(ROOT, "skills"),
      modules: false,
    });
    assert.equal(result.ok, true, result.stats.verdict);
    assert.equal(result.stats.errors, 0, JSON.stringify(result.stats.checks.filter((item) => item.result === "error")));
    assert.ok(result.stats.rulesLoaded > 0);
    assert.ok(result.stats.requests > 0);
    const truth = JSON.parse(await readFile(join(ROOT, "plugins/dsh-eval/ground-truth.json"), "utf8"));
    const scored = score(
      result.confirmed.map((item) => ({ class: item.class, path: item.path, method: item.method })),
      truth,
    );
    assert.equal(scored.fp, 0, JSON.stringify(scored.false_positives));
    assert.equal(scored.fn, 0, JSON.stringify(scored.false_negatives));
    assert.equal(scored.tp, truth.bugs.length);
    for (const finding of result.confirmed) {
      assert.equal(finding.status, "verified");
      assert.ok(finding.request && finding.response, finding.ruleId);
      assert.equal(finding.fingerprint.length, 64);
    }
    const sqli = result.confirmed.find((item) => item.ruleId === "sqli-boolean-items");
    assert.equal(sqli.extracted.row_count, 2);
    const ids = new Set(result.findings.map((item) => item.fingerprint));
    assert.equal(ids.size, result.findings.length);
    assert.equal(result.sarif.version, "2.1.0");
    assert.ok(result.jsonl.trim().endsWith("}"));
    assert.match(result.jsonl, /"type":"run"/);
    const benign = new Set(truth.benign.map((item) => item.path));
    assert.equal(result.findings.some((item) => benign.has(item.path)), false);
  } finally {
    child.kill();
  }
});

test("a live target with no matcher hits still writes an explained empty report", async () => {
  const server = createServer((_req, res) => {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("missing");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  try {
    const result = await runScan({ base: `http://127.0.0.1:${port}`, scopeText: "127.0.0.1" });
    assert.equal(result.ok, true);
    assert.equal(result.confirmed.length, 0);
    assert.ok(result.stats.rulesLoaded > 0);
    assert.ok(result.stats.requests > 0);
    assert.match(result.stats.verdict, /No results found/);
    assert.equal(result.sarif.runs[0].results.length, 0);
    assert.match(result.jsonl, /"type":"MODULE"/);
    assert.match(result.jsonl, /"type":"run"/);
    const dir = await mkdtemp(join(tmpdir(), "bh-scan-"));
    await writeScanOutput(dir, result);
    const sarif = JSON.parse(await readFile(join(dir, "findings.sarif"), "utf8"));
    assert.equal(sarif.version, "2.1.0");
    assert.equal(sarif.runs[0].results.length, 0);
    await rm(dir, { recursive: true, force: true });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("zero loaded rules is a broken pipeline, not a clean target", async () => {
  const result = await runScan({
    base: "http://127.0.0.1:9",
    scopeText: "127.0.0.1",
    rules: [],
    pack: { name: "bughive-rules", version: "1.0.0", rules: [] },
  });
  assert.equal(result.ok, false);
  assert.equal(result.brokenReason, "no_rules");
  assert.match(result.stats.verdict, /PIPELINE BROKEN/);
  assert.equal(result.stats.requests, 0);
  assert.equal(result.sarif.version, "2.1.0");
  assert.match(result.jsonl, /"type":"MODULE"/);
});

test("an out-of-scope base is refused before any request", async () => {
  const result = await runScan({ base: "http://127.0.0.1:9", scopeText: "example.com" });
  assert.equal(result.ok, false);
  assert.equal(result.brokenReason, "out_of_scope");
  assert.equal(result.stats.requests, 0);
});
