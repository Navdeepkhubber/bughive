import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, readdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { classify, ingestStaging } from "../scripts/ingest-staging.mjs";
import { runScan } from "../plugins/dsh-scan/index.js";
import { score } from "../plugins/dsh-eval/index.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE = join(ROOT, "plugins/dsh-eval/fixture-app.mjs");
const MARKER = "SQL Injection and NoSQL Injection hunting methodology.";
const SOURCE_MARKER = "Subscription Abuse";

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

async function layout() {
  const root = await mkdtemp(join(tmpdir(), "bh-ingest-"));
  const staging = join(root, "staging");
  const learned = join(root, "learned");
  const seeds = join(root, "seeds");
  const { mkdir } = await import("node:fs/promises");
  await mkdir(staging);
  await mkdir(seeds);
  await writeFile(join(seeds, "sqli.md"), "# SKILL: sqli\nHANDWRITTEN\n");
  await writeFile(join(staging, "hunt-sqli.staged.md"), [
    "<!-- harvested: ctahok/hermes-bug-bounty-skills/hunt-sqli/SKILL.md on 2026-10-23T00:00:00+00:00 -->",
    "<!-- STAGING ONLY -->",
    "",
    MARKER,
    "",
  ].join("\n"));
  await writeFile(join(staging, "business-logic-hunter.staged.md"), [
    "<!-- harvested: Aetherdz/huntpack/skills/hunting/business-logic-hunter/SKILL.md on 2026-10-23T00:00:00+00:00 -->",
    "<!-- license: MIT; author: Aether; commit: abcdef; source repo license, not permission to load or promote -->",
    "<!-- STAGING ONLY -->",
    "",
    SOURCE_MARKER,
    "",
  ].join("\n"));
  await writeFile(join(staging, "report-writing.staged.md"), "<!-- harvested: Gabson0x/bountyforge/report.md on 2026-10-23T00:00:00+00:00 -->\n\nHow to write a report.\n");
  await writeFile(join(staging, "hunt-xss-sqli.staged.md"), "<!-- harvested: x/y/both.md on 2026-10-23T00:00:00+00:00 -->\n\nboth\n");
  return { root, staging, learned, seeds, report: join(root, "ingest-report.json") };
}

test("classify uses the filename and flags a file with no single class", () => {
  assert.equal(classify("hunt-xss.staged.md", "name: other\n").primary, "xss");
  assert.equal(classify("report-writing.staged.md", "name: report-writing\n").flag, "no-class");
  assert.equal(classify("hunt-xss-sqli.staged.md", "").flag, "ambiguous-class");
});

test("derived skills drop source sentences and permissive skills keep them", async () => {
  const dirs = await layout();
  try {
    const report = await ingestStaging(dirs);
    assert.equal(report.ingested, 2);
    assert.equal(report.flagged, 2);
    const sqli = await readFile(join(dirs.learned, "staged-hunt-sqli.md"), "utf8");
    assert.equal(sqli.includes(MARKER), false);
    assert.match(sqli, /# SKILL: sqli/);
    assert.match(sqli, /"mode": "derived"/);
    assert.equal(sqli.includes("STAGING ONLY"), false);
    const logic = await readFile(join(dirs.learned, "staged-business-logic-hunter.md"), "utf8");
    assert.match(logic, /"mode": "permissive-copy"/);
    assert.match(logic, new RegExp(SOURCE_MARKER));
    assert.match(logic, /author: Aether|Aether/);
    const seed = await readFile(join(dirs.seeds, "business-logic.md"), "utf8");
    assert.equal(seed.includes(SOURCE_MARKER), false);
    assert.equal(seed.includes("STAGING ONLY"), false);
    const handwritten = await readFile(join(dirs.seeds, "sqli.md"), "utf8");
    assert.match(handwritten, /HANDWRITTEN/);
    assert.equal(await readFile(join(dirs.learned, "staged-report-writing.md"), "utf8").catch(() => ""), "");
    const again = await ingestStaging(dirs);
    assert.deepEqual(again, report);
    const sqliAgain = await readFile(join(dirs.learned, "staged-hunt-sqli.md"), "utf8");
    assert.equal(sqliAgain, sqli);
  } finally {
    await rm(dirs.root, { recursive: true, force: true });
  }
});

test("dry-run writes nothing", async () => {
  const dirs = await layout();
  try {
    const report = await ingestStaging({ ...dirs, dryRun: true });
    assert.equal(report.ingested, 2);
    assert.equal((await readdir(dirs.root)).includes("learned"), false);
    assert.deepEqual(await readdir(dirs.seeds), ["sqli.md"]);
  } finally {
    await rm(dirs.root, { recursive: true, force: true });
  }
});

test("real staging promotes covered classes and the fixture stays exact", { timeout: 120_000 }, async () => {
  const root = await mkdtemp(join(tmpdir(), "bh-real-"));
  const learned = join(root, "learned");
  const seeds = join(root, "seeds");
  try {
    const report = await ingestStaging({
      staging: join(ROOT, "skills/staging"),
      learned,
      seeds,
      report: join(root, "ingest-report.json"),
    });
    const staged = (await readdir(join(ROOT, "skills/staging"))).filter((name) => name.endsWith(".staged.md"));
    assert.equal(report.ingested + report.flagged, staged.length);
    assert.ok(report.ingested > 0);
    assert.ok(report.flagged > 0);
    const classes = new Set(report.files.filter((row) => row.status === "ingested").flatMap((row) => row.classes));
    for (const name of ["sqli", "xss", "idor", "ssrf", "ssti", "xxe", "graphql", "race-condition", "cache-poisoning", "missing-auth"]) {
      assert.equal(classes.has(name), true, name);
    }
    const sqliName = (await readdir(learned)).find((name) => name.includes("hunt-sqli"));
    const sqli = await readFile(join(learned, sqliName), "utf8");
    assert.equal(sqli.includes(MARKER), false);
    for (const name of await readdir(seeds)) {
      const text = await readFile(join(seeds, name), "utf8");
      assert.equal(text.includes("STAGING ONLY"), false, name);
      assert.equal(text.includes("harvested:"), false, name);
      assert.equal(text.includes(MARKER), false, name);
    }
    const logic = report.files.find((row) => row.staged.includes("business-logic-hunter"));
    assert.equal(logic.mode, "permissive-copy");
    assert.equal(logic.source_license, "MIT");

    const port = 18124;
    const child = await startFixture(port);
    try {
      const result = await runScan({
        base: `http://127.0.0.1:${port}`,
        scopeText: "127.0.0.1",
        skillsDir: join(ROOT, "skills"),
        modules: false,
        skillCoverage: report,
      });
      const truth = JSON.parse(await readFile(join(ROOT, "plugins/dsh-eval/ground-truth.json"), "utf8"));
      const scored = score(
        result.confirmed.map((item) => ({ class: item.class, path: item.path, method: item.method })),
        truth,
      );
      assert.equal(scored.fp, 0, JSON.stringify(scored.false_positives));
      assert.equal(scored.tp, truth.bugs.length);
      const sqliHit = result.confirmed.find((item) => item.ruleId === "sqli-boolean-items");
      assert.ok(sqliHit.coveredBy.some((id) => id.startsWith("learned/staged-")));
      for (const finding of result.confirmed) {
        if (!classes.has(finding.class)) continue;
        assert.ok(finding.coveredBy?.length, finding.class);
        assert.ok(finding.coveredBy.every((id) => id.startsWith("learned/staged-")), finding.class);
      }
    } finally {
      child.kill();
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
