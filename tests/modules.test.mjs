import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { runScan, validatePack } from "../plugins/dsh-scan/index.js";
import { PACK } from "../plugins/dsh-scan/pack.js";
import { nucleiArgs, osvScannerArgs, trufflehogArgs } from "../plugins/dsh-scan/modules.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SKILLS = join(ROOT, "skills");
const KEY = "AKIABUGHIVECANARYKEY";

function mockTransport() {
  return async (spec) => ({
    status: 404,
    headers: { "content-type": "text/plain" },
    body: "missing",
    ms: 1,
    request: { method: spec.method || "GET", url: `http://127.0.0.1${spec.path || "/"}`, headers: {}, body: "" },
    response: { status: 404, headers: {}, body: "missing" },
  });
}

test("validate accepts the pinned pack and rejects a dangling flow id", () => {
  const ok = validatePack(PACK, SKILLS);
  assert.equal(ok.ok, true, ok.errors.join("; "));
  assert.ok(ok.rulesLoaded > 0);
  const bad = validatePack({
    name: "broken",
    version: "0",
    rules: [{
      id: "dangling",
      class: "sqli",
      skill: "seeds/sqli",
      severity: "high",
      method: "GET",
      path: "/api/items",
      requests: [{ id: "base", method: "GET", path: "/api/items" }],
      matchers: [{ type: "status", request: "base", value: 200 }],
      flow: ["missing"],
    }],
  }, SKILLS);
  assert.equal(bad.ok, false);
  assert.equal(bad.rulesLoaded, 0);
  assert.match(bad.errors.join(" "), /flow id missing/);
});

test("cli --validate does not need a target", () => {
  const res = spawnSync(process.execPath, ["plugins/dsh-scan/cli.mjs", "--validate"], { cwd: ROOT, encoding: "utf8" });
  assert.equal(res.status, 0, res.stderr);
  const body = JSON.parse(res.stdout);
  assert.equal(body.ok, true);
  assert.equal(body.version, "1.1.0");
  assert.ok(body.rulesLoaded > 0);
});

test("flow runs in the declared order and extractors redact secrets", async () => {
  const seen = [];
  const rule = {
    id: "flow-order",
    class: "sqli",
    skill: "seeds/sqli",
    severity: "high",
    method: "GET",
    path: "/api/items",
    requests: [
      { id: "base", method: "GET", path: "/api/items" },
      { id: "yes", method: "GET", path: "/api/items" },
      { id: "no", method: "GET", path: "/api/items" },
    ],
    flow: ["yes", "base", "no"],
    extractors: [
      { type: "json", name: "row_count", request: "yes", path: "items.length" },
      { type: "regex", name: "leak", request: "yes", regex: "AKIA[0-9A-Z]{16}" },
    ],
    matchers: [
      { type: "json", request: "yes", path: "items.length", compare: "gt", other: "base", otherPath: "items.length" },
      { type: "json", request: "no", path: "items.length", compare: "lt", other: "yes", otherPath: "items.length" },
    ],
  };
  const result = await runScan({
    base: "http://127.0.0.1:9",
    scopeText: "127.0.0.1",
    modules: false,
    pack: { name: "flow", version: "0", rules: [rule] },
    rules: [rule],
    request: async (spec) => {
      if (spec.id) seen.push(spec.id);
      const count = spec.id === "yes" ? 2 : spec.id === "no" ? 0 : 1;
      const note = spec.id === "yes" ? KEY : "plain";
      const body = JSON.stringify({ items: Array.from({ length: count }, (_, i) => i + 1), note });
      return {
        status: 200,
        headers: {},
        body,
        ms: 1,
        request: { method: "GET", url: `http://127.0.0.1/api/items?step=${spec.id || "live"}`, headers: {}, body: "" },
        response: { status: 200, headers: {}, body: "{\"items\":[]}" },
      };
    },
  });
  assert.equal(result.ok, true, result.stats.verdict);
  assert.deepEqual(seen, ["yes", "base", "no"]);
  const hit = result.confirmed.find((item) => item.ruleId === "flow-order");
  assert.ok(hit);
  assert.equal(hit.extracted.row_count, 2);
  assert.equal(hit.extracted.leak, "AKIA[redacted]");
  assert.equal(JSON.stringify(hit.extracted).includes(KEY), false);
});

test("nuclei JSONL with a saved exchange is confirmed and deduped", async () => {
  const calls = [];
  const line = JSON.stringify({
    "template-id": "bughive-demo",
    info: { severity: "high" },
    "matched-at": "http://127.0.0.1:9/.git/config",
    request: `GET /.git/config HTTP/1.1\r\nAuthorization: Bearer ${KEY}\r\n\r\n`,
    response: "HTTP/1.1 200 OK\r\n\r\n[core]",
    "extracted-results": [KEY],
  });
  const result = await runScan({
    base: "http://127.0.0.1:9",
    scopeText: "127.0.0.1",
    request: mockTransport(),
    whichImpl: (bin) => (bin === "nuclei" ? "/usr/bin/nuclei" : null),
    spawnImpl: (bin, args) => {
      calls.push([bin, args]);
      return { status: 1, stdout: `${line}\n${line}\n`, stderr: "findings" };
    },
  });
  assert.deepEqual(calls[0][1], nucleiArgs("http://127.0.0.1:9"));
  assert.equal(calls[0][1].includes("-t"), false);
  assert.equal(result.stats.moduleRuns.nuclei.status, "ran");
  const hits = result.findings.filter((item) => item.ruleId === "bughive-demo");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].status, "verified");
  assert.equal(result.confirmed.some((item) => item.ruleId === "bughive-demo"), true);
  assert.equal(JSON.stringify(hits).includes(KEY), false);
  assert.equal(result.sarif.runs[0].tool.driver.rules.some((rule) => rule.id === "bughive-demo"), true);
  assert.match(result.jsonl, /"type":"MODULE"/);
  assert.match(result.jsonl, /"type":"VULNERABILITY"/);
});

test("nuclei without a response stays unverified", async () => {
  const result = await runScan({
    base: "http://127.0.0.1:9",
    scopeText: "127.0.0.1",
    request: mockTransport(),
    whichImpl: (bin) => (bin === "nuclei" ? "/usr/bin/nuclei" : null),
    spawnImpl: () => ({
      status: 0,
      stdout: `${JSON.stringify({ "template-id": "partial", info: { severity: "low" }, "matched-at": "http://127.0.0.1:9/x", request: "GET /x", response: "" })}\n`,
      stderr: "",
    }),
  });
  const hit = result.findings.find((item) => item.ruleId === "partial");
  assert.ok(hit);
  assert.equal(hit.status, "unverified");
  assert.equal(result.confirmed.some((item) => item.ruleId === "partial"), false);
});

test("a nuclei crash with empty stdout is a module error, not zero findings", async () => {
  const result = await runScan({
    base: "http://127.0.0.1:9",
    scopeText: "127.0.0.1",
    request: mockTransport(),
    whichImpl: (bin) => (bin === "nuclei" ? "/usr/bin/nuclei" : null),
    spawnImpl: () => ({ status: 2, stdout: "", stderr: "template load failed" }),
  });
  assert.equal(result.ok, true);
  assert.equal(result.stats.moduleRuns.nuclei.status, "error");
  assert.match(result.stats.moduleRuns.nuclei.error, /template load failed/);
  assert.ok(result.stats.errors >= 1);
  assert.equal(result.findings.some((item) => item.module === "nuclei"), false);
  assert.match(result.jsonl, /"module":"nuclei","status":"error"/);
});

test("nuclei does not run against a non-loopback host unless active proof is on", async () => {
  let spawned = 0;
  const result = await runScan({
    base: "http://example.com",
    scopeText: "example.com",
    allowActive: false,
    request: mockTransport(),
    whichImpl: (bin) => (bin === "nuclei" || bin === "bbot" ? `/usr/bin/${bin}` : null),
    spawnImpl: () => {
      spawned += 1;
      return { status: 0, stdout: "", stderr: "" };
    },
  });
  assert.equal(spawned, 0);
  assert.equal(result.stats.moduleRuns.nuclei.status, "skipped");
  assert.equal(result.stats.moduleRuns.bbot.status, "skipped");
  assert.match(result.stats.moduleRuns.bbot.detail, /not started/);
});

test("trufflehog verified is confirmed, unverified is not, and example keys are dropped", async () => {
  const dir = await mkdtemp(join(tmpdir(), "bh-th-"));
  const file = join(dir, "notes.txt");
  await writeFile(file, "nothing to see\n");
  const rows = [
    { DetectorName: "AWS", Verified: false, Raw: KEY, Redacted: "AKIA[redacted]", SourceMetadata: { Data: { Filesystem: { file, line: 3 } } } },
    { DetectorName: "AWS", Verified: true, Raw: "AKIAIOSFODNN7EXAMPLE", Redacted: "AKIAIOSFODNN7EXAMPLE", SourceMetadata: { Data: { Filesystem: { file, line: 1 } } } },
    { DetectorName: "Github", Verified: true, Raw: "ghp_supersecretvalue", Redacted: "ghp_***", SourceMetadata: { Data: { Filesystem: { file, line: 4 } } } },
  ];
  const calls = [];
  const result = await runScan({
    paths: [file],
    scopeText: "127.0.0.1",
    whichImpl: (bin) => (bin === "trufflehog" ? "/usr/bin/trufflehog" : null),
    spawnImpl: (bin, args) => {
      calls.push(args);
      return { status: 0, stdout: `${rows.map((row) => JSON.stringify(row)).join("\n")}\n`, stderr: "" };
    },
  });
  assert.deepEqual(calls[0], trufflehogArgs(file));
  const unverified = result.findings.find((item) => item.module === "trufflehog" && item.status === "unverified");
  assert.ok(unverified);
  assert.equal(result.confirmed.some((item) => item.ruleId === unverified.ruleId && item.asset === unverified.asset), false);
  const verified = result.confirmed.filter((item) => item.module === "trufflehog");
  assert.equal(verified.length, 1);
  assert.match(verified[0].proof, /Github/);
  assert.ok(verified[0].request && verified[0].response);
  const dumped = JSON.stringify(result.findings);
  assert.equal(dumped.includes(KEY), false);
  assert.equal(dumped.includes("ghp_supersecretvalue"), false);
  assert.equal(dumped.includes("AKIAIOSFODNN7EXAMPLE"), false);
});

test("osv-scanner JSON is confirmed and the API fallback is not called", async () => {
  let fetched = 0;
  const result = await runScan({
    packageJson: join(ROOT, "canaries/lockfile/package.json"),
    scopeText: "127.0.0.1",
    whichImpl: (bin) => (bin === "osv-scanner" ? "/usr/bin/osv-scanner" : null),
    spawnImpl: (bin, args) => {
      assert.deepEqual(args, osvScannerArgs(join(ROOT, "canaries/lockfile/package.json")));
      return {
        status: 0,
        stdout: JSON.stringify({
          results: [{
            packages: [{
              package: { name: "lodash", version: "4.17.20" },
              vulnerabilities: [{ id: "GHSA-35jh-r3h4-6jhm", summary: "prototype pollution", aliases: ["CVE-2021-23337"], details: "x".repeat(5000) }],
            }],
          }],
        }),
        stderr: "",
      };
    },
    fetchImpl: async () => {
      fetched += 1;
      throw new Error("api.osv.dev should not be called when osv-scanner ran");
    },
  });
  assert.equal(fetched, 0);
  assert.equal(result.stats.moduleRuns["osv-scanner"].status, "ran");
  const hit = result.confirmed.find((item) => item.advisories?.includes("GHSA-35jh-r3h4-6jhm"));
  assert.ok(hit, result.stats.verdict);
  assert.match(hit.response.body, /GHSA-35jh-r3h4-6jhm/);
  assert.equal(hit.response.body.includes("xxxxx"), false);
  assert.equal(result.stats.modules["osv-scanner"], "present");
});

test("a failed osv-scanner falls back to the API query", async () => {
  let fetched = 0;
  const result = await runScan({
    packageJson: join(ROOT, "canaries/lockfile/package.json"),
    scopeText: "127.0.0.1",
    whichImpl: (bin) => (bin === "osv-scanner" ? "/usr/bin/osv-scanner" : null),
    spawnImpl: () => ({ status: 2, stdout: "", stderr: "scanner broke" }),
    fetchImpl: async () => {
      fetched += 1;
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({ vulns: [{ id: "GHSA-35jh-r3h4-6jhm", summary: "prototype pollution", aliases: [] }] });
        },
      };
    },
  });
  assert.equal(fetched, 1);
  assert.equal(result.stats.moduleRuns["osv-scanner"].status, "error");
  const hit = result.confirmed.find((item) => item.ruleId === "sca-osv-npm");
  assert.ok(hit);
  assert.ok(hit.advisories.includes("GHSA-35jh-r3h4-6jhm"));
});
