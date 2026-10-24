import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseProgramText, encodeScopedHost, isPublicSuffix, registrableDomain } from "../plugins/dsh-scope-intake/index.js";
import { sniffExtension } from "../plugins/dsh-js-analyzer/cli.mjs";
import {
  applyPolicy,
  huntSnapshot,
  legalPhases,
  phasesFromSignals,
  reconWallExceeded,
  highSignalReconPresent,
  RECON_MAX_SECONDS,
} from "../scripts/pipeline/jev-decide.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function py(code) {
  return JSON.parse(execFileSync("python3", ["-c", code], { cwd: ROOT, encoding: "utf8" }));
}

const SCOPE_HELPERS = `
import json, sys
sys.path.insert(0, "scripts/pipeline")
from _scope import enum_roots, is_public_suffix, registrable_domain
from _recon_safety import (
    httpx_truncated, is_scannable_public_ip, normalize_asset_url,
    asset_filename, unique_registrable_roots,
)
`;

test("enum_roots refuses public suffixes and keeps the private label", () => {
  const out = py(`${SCOPE_HELPERS}
roots = enum_roots("**.www.airnewzealand.co.jp\\n*.airnewzealand.com.au\\n*.synedra.com\\ng-*.0.threema.ch\\nco.nz\\n")
print(json.dumps({
  "roots": roots,
  "co_jp": is_public_suffix("co.jp"),
  "com_au": is_public_suffix("com.au"),
  "co_nz": is_public_suffix("co.nz"),
  "reg": registrable_domain("www.airnewzealand.co.jp"),
  "brand": is_public_suffix("airnewzealand.co.jp"),
  "synedra": is_public_suffix("synedra.com"),
}))
`);
  assert.equal(out.co_jp, true);
  assert.equal(out.com_au, true);
  assert.equal(out.co_nz, true);
  assert.equal(out.brand, false);
  assert.equal(out.synedra, false);
  assert.equal(out.reg, "airnewzealand.co.jp");
  assert.ok(!out.roots.includes("co.jp"));
  assert.ok(!out.roots.includes("com.au"));
  assert.ok(!out.roots.includes("co.nz"));
  assert.ok(!out.roots.includes("com"));
  assert.ok(out.roots.includes("www.airnewzealand.co.jp"));
  assert.ok(out.roots.includes("synedra.com"));
  assert.ok(out.roots.includes("0.threema.ch"));
  assert.ok(out.roots.includes("threema.ch"));
  assert.equal(isPublicSuffix("co.jp"), true);
  assert.equal(registrableDomain("www.airnewzealand.co.jp"), "airnewzealand.co.jp");
  assert.equal(isPublicSuffix("synedra.com"), false);
});

test("scope intake does not rewrite www hosts into public-suffix wildcards", () => {
  const named = parseProgramText("In scope:\nwww.airnewzealand.co.jp\nwww.airnewzealand.com\n");
  assert.deepEqual(named.in_scope, ["www.airnewzealand.co.jp", "www.airnewzealand.com"]);

  const withSubs = parseProgramText(
    "The following hosts and their subdomains are in scope:\nwww.airnewzealand.co.jp\nwww.airnewzealand.com.au\n",
  );
  assert.ok(withSubs.in_scope.includes("www.airnewzealand.co.jp"));
  assert.ok(withSubs.in_scope.includes("*.www.airnewzealand.co.jp"));
  assert.ok(withSubs.in_scope.includes("*.www.airnewzealand.com.au"));
  assert.ok(!withSubs.in_scope.some((h) => h === "co.jp" || h === "com.au" || h.startsWith("**.www.")));
  assert.ok(!withSubs.in_scope.includes("p-airnz.com"));
  assert.ok(!withSubs.in_scope.includes("flightbookings.airnewzealand.com"));
  assert.deepEqual(encodeScopedHost("**.www.airnewzealand.co.uk"), [
    "www.airnewzealand.co.uk",
    "*.www.airnewzealand.co.uk",
  ]);
});

test("httpx truncation and non-public addresses are not a clean success", () => {
  const out = py(`${SCOPE_HELPERS}
print(json.dumps({
  "killed": httpx_truncated(124, 58, 58),
  "short": httpx_truncated(0, 427, 6),
  "full": httpx_truncated(0, 58, 50),
  "small": httpx_truncated(0, 4, 1),
  "priv": is_scannable_public_ip("10.205.62.120"),
  "loop": is_scannable_public_ip("127.0.0.1"),
  "link": is_scannable_public_ip("169.254.1.1"),
  "cgnat": is_scannable_public_ip("100.64.0.1"),
  "pub": is_scannable_public_ip("1.1.1.1"),
  "url": normalize_asset_url("http://www.airnewzealand.ca:80//appsettings.js"),
  "name": asset_filename("https://www.airnewzealand.ca/appsettings.js"),
  "roots": unique_registrable_roots([
    "www.airnewzealand.co.jp", "airnewzealand.co.jp", "co.jp",
    "www.airnewzealand.com.au", "www.airnewzealand.co.nz",
    "www.airnewzealand.co.uk", "www.airnewzealand.com",
  ], 4)[0],
  "root_total": unique_registrable_roots([
    "www.airnewzealand.co.jp", "www.airnewzealand.com.au",
    "www.airnewzealand.co.nz", "www.airnewzealand.co.uk",
    "www.airnewzealand.com",
  ], 4)[1],
}))
`);
  assert.equal(out.killed, true);
  assert.equal(out.short, true);
  assert.equal(out.full, false);
  assert.equal(out.small, false);
  assert.equal(out.priv, false);
  assert.equal(out.loop, false);
  assert.equal(out.link, false);
  assert.equal(out.cgnat, false);
  assert.equal(out.pub, true);
  assert.equal(out.url, "https://www.airnewzealand.ca/appsettings.js");
  assert.match(out.name, /^[a-f0-9]{32}\.js$/);
  assert.ok(!out.roots.includes("co.jp"));
  assert.equal(out.roots.length, 4);
  assert.equal(out.root_total, 5);
});

test("normalize keeps in-scope asset names and drops sibling hosts", async () => {
  const dir = await mkdtemp(join(tmpdir(), "bh-assets-"));
  const scope = join(dir, "scope.txt");
  const raw = join(dir, "raw.txt");
  await writeFile(scope, "www.airnewzealand.com\n*.www.airnewzealand.com\n");
  await writeFile(raw, [
    "http://www.airnewzealand.ca:80//appsettings.js",
    "https://www.airnewzealand.com/static/app.js",
    "https://p-airnz.com/bundle.js",
    "https://flightbookings.airnewzealand.com/main.js",
    "https://cdn.www.airnewzealand.com/widget.js",
  ].join("\n"));
  try {
    const out = py(`
import json, sys
sys.path.insert(0, "scripts/pipeline")
from pathlib import Path
from urllib.parse import urlsplit
from _recon_safety import normalize_asset_url, asset_filename
from _scope import scope_allows
scope = Path(${JSON.stringify(scope)}).read_text()
seen, dropped = [], []
for line in Path(${JSON.stringify(raw)}).read_text().splitlines():
    norm = normalize_asset_url(line.strip())
    host = urlsplit(norm).hostname or ""
    row = {"url": norm, "name": asset_filename(norm), "host": host}
    (seen if scope_allows(scope, host)[0] else dropped).append(row)
print(json.dumps({"seen": seen, "dropped": dropped}))
`);
    assert.deepEqual(out.seen.map((r) => r.host), ["www.airnewzealand.com", "cdn.www.airnewzealand.com"]);
    assert.ok(out.seen.every((r) => r.name.endsWith(".js")));
    assert.ok(out.dropped.some((r) => r.host === "p-airnz.com"));
    assert.ok(out.dropped.some((r) => r.host === "flightbookings.airnewzealand.com"));
    assert.ok(out.dropped.some((r) => r.host === "www.airnewzealand.ca"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("extensionless JS and HTML are scannable; plain text is not", async () => {
  assert.equal(sniffExtension("function boot(){ document.write('x') }\n"), ".js");
  assert.equal(sniffExtension("<html><head><title>301</title></head><body>moved</body></html>"), ".html");
  assert.equal(sniffExtension("hello from a redirect note"), "");
  const dir = await mkdtemp(join(tmpdir(), "bh-js-"));
  const out = join(dir, "out");
  await mkdir(out);
  await writeFile(join(dir, "bundle"), "function boot(){ document.write(location.hash) }\n");
  await writeFile(join(dir, "note"), "this is not code\n");
  try {
    const raw = execFileSync(process.execPath, [
      join(ROOT, "plugins/dsh-js-analyzer/cli.mjs"),
      dir,
      "--out",
      out,
    ], { encoding: "utf8" });
    const summary = JSON.parse(await readFile(join(out, "summary.json"), "utf8"));
    assert.equal(summary.files_scanned, 1);
    assert.match(raw, /"files_scanned":\s*1/);
    assert.ok(!summary.notes.includes("no scannable assets found under the scan dirs"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a phase is done from summary.json or the recon-NN.done marker", () => {
  const fromDone = phasesFromSignals({ summaryIds: [], doneStages: ["recon-03", "recon-09"] });
  assert.ok(fromDone.present.includes("03-port-scan"));
  assert.ok(fromDone.present.includes("09-historical-data"));
  assert.deepEqual(fromDone.placeholders.sort(), ["03-port-scan", "09-historical-data"].sort());
  assert.ok(!legalPhases(fromDone.present).includes("03-port-scan"));
  assert.ok(!legalPhases(fromDone.present).includes("09-historical-data"));
  const both = phasesFromSignals({
    summaryIds: ["04-http-probe"],
    doneStages: ["recon-04", "recon-07"],
  });
  assert.ok(both.present.includes("04-http-probe"));
  assert.ok(both.present.includes("07-js-analysis"));
  assert.deepEqual(both.placeholders, ["07-js-analysis"]);
});

test("timeout writes a degraded summary and marks the phase done", () => {
  const hunts = execFileSync("mktemp", ["-d"], { encoding: "utf8" }).trim();
  const script = `
set -euo pipefail
source scripts/pipeline/_common.sh
HUNTS=${JSON.stringify(hunts)}
ensure_recon_summary "example.test" "recon-09" 124
ensure_recon_summary "example.test" "recon-03" 1
# A phase that ended cleanly but forgot summary.json still records degraded.
ensure_recon_summary "other.test" "recon-07" 0
echo $(($(date +%s) - 125)) > "$HUNTS/example.test/.state/recon-phase-start"
recon_phase_end "example.test"
`;
  try {
    execFileSync("bash", ["-c", script], { cwd: ROOT, encoding: "utf8" });
    const summary = JSON.parse(execFileSync("cat", [
      join(hunts, "example.test/recon/09-historical-data/summary.json"),
    ], { encoding: "utf8" }));
    assert.equal(summary.degraded, true);
    assert.match(summary.notes[0], /timed out/);
    execFileSync("test", ["-f", join(hunts, "example.test/.state/recon-09.done")]);
    let missing = false;
    try {
      execFileSync("test", ["-e", join(hunts, "example.test/recon/03-port-scan/summary.json")]);
    } catch {
      missing = true;
    }
    assert.equal(missing, true, "a hard failure must not be rewritten into a finished phase");
    const skipped = JSON.parse(execFileSync("cat", [
      join(hunts, "other.test/recon/07-js-analysis/summary.json"),
    ], { encoding: "utf8" }));
    assert.equal(skipped.degraded, true);
    const elapsed = Number(execFileSync("cat", [
      join(hunts, "example.test/.state/recon-elapsed-seconds"),
    ], { encoding: "utf8" }).trim());
    assert.ok(elapsed >= 120 && elapsed <= 140, `elapsed ${elapsed}`);
  } finally {
    execFileSync("rm", ["-rf", hunts]);
  }
});

test("hunt snapshot treats a done marker without summary as present and degraded", async () => {
  const domain = "recon-safety.invalid";
  const hunt = join(ROOT, "hunts", domain);
  await rm(hunt, { recursive: true, force: true });
  await mkdir(join(hunt, ".state"), { recursive: true });
  await mkdir(join(hunt, "recon", "04-http-probe"), { recursive: true });
  await writeFile(join(hunt, "recon", "04-http-probe", "summary.json"), JSON.stringify({
    phase: "04-http-probe", count: 2,
  }));
  await writeFile(join(hunt, ".state", "recon-09.done"), "2026-10-24T00:00:00Z\n");
  await writeFile(join(hunt, ".state", "recon-elapsed-seconds"), "2400\n");
  try {
    const snap = await huntSnapshot(domain);
    assert.ok(snap.present.includes("04-http-probe"));
    assert.ok(snap.present.includes("09-historical-data"));
    assert.equal(snap.recon["09-historical-data"].degraded, true);
    assert.ok(!snap.legal.includes("09-historical-data"));
    assert.equal(snap.recon_elapsed_seconds, 2400);
    assert.equal(snap.recon_max_seconds, Number(process.env.BUGHIVE_RECON_MAX_SECONDS) || RECON_MAX_SECONDS);
    assert.equal(reconWallExceeded(snap), true);
  } finally {
    await rm(hunt, { recursive: true, force: true });
  }
});

function policySnap(overrides = {}) {
  return {
    hd: "/tmp/jev-unused",
    done: ["scope", "recon-04"],
    recon: { "04-http-probe": { count: 2, items: [{ url: "https://www.example.com/" }] } },
    present: ["04-http-probe"],
    legal: ["07-js-analysis", "09-historical-data", "14-nuclei-scan"],
    missing: ["14-nuclei-scan"],
    keyword: [{ skill: "seeds/idor", score: 4, matched_terms: "userid" }],
    hasKeyword: true,
    hasSelected: true,
    counts: { hypotheses: 0, hypotheses_pass: 0, hypotheses_real: 0, validated: 0, reports: 0, approved: 0 },
    recon_elapsed_seconds: 0,
    recon_max_seconds: 1200,
    ...overrides,
  };
}

function routing(action, extra = {}) {
  return {
    model: "jev-test",
    usage: null,
    answers: {
      next_action: { choice: action, confidence: 0.9, probabilities: {} },
      recon_phase: { choice: "09_historical_data", confidence: 0.8, probabilities: {} },
      signal: { score: 1, confidence: 0.5 },
      worth_testing: { noul: 0.1 },
      human_review: { noul: 0.1 },
      skill: { choice: "seeds__idor", confidence: 0.7, probabilities: { seeds__idor: 0.7 } },
      ...extra,
    },
  };
}

const skills = [{ id: "seeds/idor", key: "seeds__idor", blurb: "swap object ids" }];

test("thin evidence still deepens recon while the budget and high-signal phases are open", () => {
  const decision = applyPolicy({
    snap: policySnap(),
    skills,
    routing: routing("select_and_test"),
    confirm: null,
  }, { routingOnly: true });
  assert.equal(decision.next_action, "deepen_recon");
  assert.equal(highSignalReconPresent(policySnap()), false);
});

test("recon runtime cap leaves recon even when legal phases remain", () => {
  const snap = policySnap({ recon_elapsed_seconds: 1200, recon_max_seconds: 1200 });
  assert.equal(reconWallExceeded(snap), true);
  const deepened = applyPolicy({
    snap,
    skills,
    routing: routing("deepen_recon"),
    confirm: null,
  }, { routingOnly: true });
  assert.equal(deepened.next_action, "select_and_test");
  assert.equal(deepened.recon_phase, null);
  assert.equal(deepened.recon_budget_exceeded, true);
  assert.equal(deepened.clamped_from, "deepen_recon");

  const unscored = applyPolicy({
    snap: { ...snap, hasKeyword: false, keyword: [] },
    skills,
    routing: routing("deepen_recon"),
    confirm: null,
  }, { routingOnly: true });
  assert.equal(unscored.next_action, "score_skills");

  const thin = applyPolicy({
    snap,
    skills,
    routing: routing("select_and_test"),
    confirm: null,
  }, { routingOnly: true });
  assert.equal(thin.next_action, "select_and_test");
});

test("high-signal phases keep select_and_test instead of forcing more recon", () => {
  const snap = policySnap({
    present: ["04-http-probe", "07-js-analysis"],
    recon: {
      "04-http-probe": { count: 2 },
      "07-js-analysis": { count: 1, files_scanned: 3 },
    },
  });
  assert.equal(highSignalReconPresent(snap), true);
  const decision = applyPolicy({
    snap,
    skills,
    routing: routing("select_and_test"),
    confirm: null,
  }, { routingOnly: true });
  assert.equal(decision.next_action, "select_and_test");
  assert.notEqual(decision.next_action, "deepen_recon");
});

test("coverage still blocks deliver after the recon budget is spent", () => {
  const snap = policySnap({
    recon_elapsed_seconds: 5000,
    coverage: { present: true, critical_completion_pct: 10, blocking_count: 40 },
    counts: { hypotheses: 0, hypotheses_pass: 0, hypotheses_real: 0, validated: 0, reports: 0, approved: 0 },
  });
  const decision = applyPolicy({
    snap,
    skills,
    routing: routing("deliver", {
      worth_testing: { noul: 0.9 },
      human_review: { noul: 0.1 },
    }),
    confirm: null,
  }, { routingOnly: true });
  assert.equal(decision.next_action, "human_gate");
  assert.equal(decision.clamped_from, "deliver");
});
