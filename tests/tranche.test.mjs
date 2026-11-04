import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildExecutor } from "../scripts/pipeline/jev-decide.mjs";
import { buildPlan } from "../scripts/pipeline/batch-run.mjs";
import {
  ACTIVE_STAGES,
  PASSIVE_STAGES,
  advanceBatchState,
  applyStageBounds,
  batchRequiredFromScope,
  initialBatchState,
  loadBatchConfig,
  nextBatchUnit,
  rankHosts,
  scoreHost,
  splitTranches,
  stageArgs,
  trancheMayAdvance,
} from "../scripts/pipeline/tranche.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

test("batch knobs default to the brief and stay overridable", () => {
  const cfg = loadBatchConfig({});
  assert.equal(cfg.batchDomains, 1);
  assert.equal(cfg.trancheHostCap, 1);
  assert.equal(cfg.passiveUrlCap, 1500);
  assert.equal(cfg.jsFetchCap, 50);
  assert.equal(cfg.httpx.threads, 50);
  assert.equal(cfg.httpx.rateLimit, 150);
  assert.equal(cfg.httpx.budgetSeconds, 300);
  assert.equal(cfg.katana.concurrency, 10);
  assert.equal(cfg.katana.parallelism, 5);
  assert.equal(cfg.katana.rateLimit, 100);
  assert.equal(cfg.katana.depth, 2);
  assert.equal(cfg.katana.hostRateLimit, 20);
  assert.equal(cfg.katana.perHostSeconds, 90);
  assert.equal(cfg.katana.budgetSeconds, 900);
  assert.equal(cfg.naabu.scanType, "s");
  assert.equal(cfg.naabu.rate, 1000);
  assert.equal(cfg.naabu.concurrency, 100);
  assert.equal(cfg.naabu.retries, 1);
  assert.equal(cfg.naabu.topPorts, 1000);
  assert.equal(cfg.naabu.budgetSeconds, 600);
  assert.equal(cfg.nuclei.rateLimit, 150);
  assert.equal(cfg.nuclei.concurrency, 25);
  assert.equal(cfg.nuclei.bulkSize, 25);
  assert.equal(cfg.nuclei.severityFirst, "critical,high");
  assert.equal(cfg.nuclei.budgetSeconds, 1200);
  assert.equal(cfg.gau.threads, 5);
  assert.equal(cfg.gau.budgetSeconds, 300);
  assert.equal(cfg.gau.providers, "wayback");
  assert.ok(stageArgs("katana", cfg).includes("-hrl"));
  assert.ok(stageArgs("naabu", cfg).includes("-top-ports"));
  assert.ok(stageArgs("gau", cfg).includes("--blacklist"));

  const tuned = loadBatchConfig({
    BUGHIVE_BATCH_DOMAINS: "3",
    BUGHIVE_TRANCHE_HOST_CAP: "7",
    BUGHIVE_HTTPX_BUDGET_SECONDS: "12",
    BUGHIVE_PASSIVE_URL_CAP: "1000",
  });
  assert.equal(tuned.batchDomains, 3);
  assert.equal(tuned.trancheHostCap, 7);
  assert.equal(tuned.httpx.budgetSeconds, 12);
  assert.equal(tuned.passiveUrlCap, 1000);
  assert.equal(tuned.katana.budgetSeconds, 900);

  const low = loadBatchConfig({ BUGHIVE_RATE_PROFILE: "low" });
  assert.equal(low.rateProfile, "low");
  assert.equal(low.httpx.rateLimit, 5);
  assert.equal(low.httpx.threads, 2);
  assert.equal(low.nuclei.rateLimit, 5);
  assert.equal(low.nuclei.concurrency, 2);
  assert.equal(low.nuclei.bulkSize, 2);
  assert.equal(low.nmapTop, 100);
  const tunedLow = loadBatchConfig({
    BUGHIVE_RATE_PROFILE: "low",
    BUGHIVE_LOW_HTTPX_RATE: "3",
    BUGHIVE_LOW_NMAP_TOP: "80",
  });
  assert.equal(tunedLow.httpx.rateLimit, 3);
  assert.equal(tunedLow.httpx.threads, 2);
  assert.equal(tunedLow.nmapTop, 80);
  assert.equal(tunedLow.nuclei.bulkSize, 2);
});

test("tranche split respects the domain batch and spills when one root exceeds the host cap", () => {
  const cfg = loadBatchConfig({});
  const wide = ["a.com", "b.com", "c.com", "d.com", "e.com", "f.com"].map((host) => ({ host }));
  const byDomain = splitTranches(wide, cfg);
  assert.equal(byDomain.length, 6);
  assert.equal(byDomain[0].host_count, 1);
  assert.equal(byDomain[0].domains.length, 1);
  assert.equal(byDomain[5].host_count, 1);
  assert.equal(byDomain[5].domains[0], "f.com");

  const fat = Array.from({ length: 58 }, (_, i) => ({
    host: `h${String(i).padStart(2, "0")}.airnewzealand.co.nz`,
  }));
  const spilled = splitTranches(fat, cfg);
  assert.equal(spilled.length, 58);
  assert.equal(spilled[0].host_count, 1);
  assert.equal(spilled[57].host_count, 1);
  assert.equal(spilled[0].domains.length, 1);
  assert.equal(spilled[0].spilled, true);
  assert.equal(spilled[57].spilled, true);
  assert.deepEqual(spilled[0].domains, ["airnewzealand.co.nz"]);

  const both = [];
  for (const domain of ["alpha.test", "beta.test"]) {
    for (let i = 0; i < 30; i += 1) {
      both.push({ host: `n${String(i).padStart(2, "0")}.${domain}` });
    }
  }
  const mixed = splitTranches(both, loadBatchConfig({
    BUGHIVE_BATCH_DOMAINS: "5",
    BUGHIVE_TRANCHE_HOST_CAP: "40",
  }));
  assert.equal(mixed[0].host_count, 40);
  assert.ok(mixed[0].domains.includes("alpha.test"));
  assert.ok(mixed[0].domains.includes("beta.test"));
  assert.equal(mixed[1].host_count, 20);
  assert.equal(mixed[1].spilled, true);
  assert.ok(mixed[0].host_count <= 40 && mixed[1].host_count <= 40);
});

test("host ranking orders app surface above CDN and marketing, deterministically", () => {
  const cfg = loadBatchConfig({});
  const rows = [
    { host: "cdn.static.brand.test" },
    { host: "mkt.brand.test" },
    { host: "files.brand.test" },
    { host: "auth.login.brand.test" },
    { host: "api.brand.test" },
  ];
  const ranked = rankHosts(rows, cfg);
  const again = rankHosts(rows.slice().reverse(), cfg);
  assert.deepEqual(ranked.map((row) => row.host), again.map((row) => row.host));
  const order = ranked.map((row) => row.host);
  assert.ok(order.indexOf("auth.login.brand.test") < order.indexOf("api.brand.test"));
  assert.ok(order.indexOf("api.brand.test") < order.indexOf("mkt.brand.test"));
  assert.ok(order.indexOf("api.brand.test") < order.indexOf("files.brand.test"));
  assert.ok(order.indexOf("api.brand.test") < order.indexOf("cdn.static.brand.test"));
  assert.equal(order.at(-1), "cdn.static.brand.test");
  const auth = ranked.find((row) => row.host.startsWith("auth"));
  const cdn = ranked.find((row) => row.host.startsWith("cdn"));
  assert.equal(auth.tail, false);
  assert.equal(cdn.tail, true);
  assert.ok(auth.score > cdn.score);
  assert.equal(auth.score, 10);
  assert.equal(cdn.score, -10);

  const login = scoreHost({
    host: "www.brand.test",
    title: "Sign in",
    status: 200,
    location: "https://www.brand.test/login",
  }, cfg);
  assert.ok(login.reasons.some((reason) => reason.startsWith("login")));
  assert.ok(login.score >= 5);
});

test("stage bounds set degraded and truncated when the cap or the clock hits first", () => {
  const capped = applyStageBounds({
    results: ["a", "b", "c"],
    resultCap: 2,
    elapsedMs: 10,
    budgetMs: 1000,
    exitCode: 0,
  });
  assert.equal(capped.degraded, true);
  assert.equal(capped.truncated, true);
  assert.deepEqual(capped.results, ["a", "b"]);
  assert.equal(capped.count_total, 3);

  const expired = applyStageBounds({
    results: ["partial"],
    resultCap: 10,
    elapsedMs: 5000,
    budgetMs: 1000,
    exitCode: 0,
  });
  assert.equal(expired.degraded, true);
  assert.equal(expired.truncated, true);
  assert.deepEqual(expired.results, ["partial"]);
  assert.match(expired.reasons.join(" "), /wall-clock/);

  const killed = applyStageBounds({
    results: ["partial"],
    resultCap: 10,
    elapsedMs: 20,
    budgetMs: 1000,
    exitCode: 124,
  });
  assert.equal(killed.degraded, true);
  assert.equal(killed.truncated, true);
  assert.deepEqual(killed.results, ["partial"]);

  const clean = applyStageBounds({
    results: ["a", "b"],
    resultCap: 10,
    elapsedMs: 100,
    budgetMs: 1000,
    exitCode: 0,
  });
  assert.equal(clean.degraded, false);
  assert.equal(clean.truncated, false);
  assert.deepEqual(clean.results, ["a", "b"]);

  const py = JSON.parse(execFileSync(
    "python3",
    ["scripts/pipeline/_batch.py", "apply-bounds"],
    {
      cwd: ROOT,
      encoding: "utf8",
      input: JSON.stringify({
        results: ["a", "b", "c"],
        resultCap: 1,
        elapsedMs: 50,
        budgetMs: 1000,
        exitCode: 0,
      }),
    },
  ));
  assert.equal(py.degraded, true);
  assert.equal(py.truncated, true);
  assert.deepEqual(py.results, ["a"]);
});

test("the next tranche waits for confirm after the current host emits findings", () => {
  const plan = {
    tranches: [
      { index: 1, hosts: ["api.a.test"], domains: ["a.test"], tail: false },
      { index: 2, hosts: ["api.b.test"], domains: ["b.test"], tail: false },
    ],
  };
  let state = initialBatchState();
  const seen = [];
  for (let guard = 0; guard < 80 && !state.complete; guard += 1) {
    const unit = nextBatchUnit(state, plan);
    seen.push(`${unit.kind}:${unit.stage || ""}:${unit.tranche || ""}`);
    if (unit.kind === "await_confirm") {
      state = { ...state, confirmed: true };
      continue;
    }
    state = advanceBatchState(state, unit, { trancheCount: plan.tranches.length });
  }
  const emit1 = seen.findIndex((line) => line.startsWith("emit::1"));
  const active2 = seen.findIndex((line) => line === "active:recon-05:2");
  assert.ok(emit1 >= 0, seen.join("\n"));
  assert.ok(active2 > emit1, seen.join("\n"));
  assert.deepEqual(
    seen.filter((line) => line.startsWith("passive:")).map((line) => line.split(":")[1]),
    PASSIVE_STAGES,
  );
  assert.ok(seen.includes(`active:${ACTIVE_STAGES[0]}:1`));
  assert.ok(seen.includes("scan::1"));
  assert.equal(state.complete, true);

  const waiting = {
    phase: "tranche",
    passive_index: PASSIVE_STAGES.length,
    tranche_index: 0,
    active_index: ACTIVE_STAGES.length,
    scanned: true,
    findings_emitted: false,
  };
  assert.equal(nextBatchUnit(waiting, plan).kind, "emit");
  const paused = advanceBatchState(waiting, { kind: "emit" }, { trancheCount: 2 });
  assert.equal(paused.phase, "await_confirm");
  assert.equal(paused.confirmed, false);
  assert.equal(nextBatchUnit(paused, plan).kind, "await_confirm");
  assert.equal(nextBatchUnit({ ...paused, confirmed: true }, plan).kind, "advance");
  assert.equal(trancheMayAdvance({ emitted: false }), false);
  assert.equal(trancheMayAdvance({ emitted: true, findings: [] }), true);
  assert.equal(trancheMayAdvance({ findings: { emitted: true } }), true);
});

test("wide scope routes deepen_recon through the batch step without touching a narrow one", () => {
  const wide = buildExecutor({
    next_action: "deepen_recon",
    recon_phase: "03-port-scan",
    batch_active: true,
  }, "airnewzealand.com");
  assert.match(wide.command, /batch step airnewzealand\.com/);
  assert.equal(wide.kind, "bash");

  const narrow = buildExecutor({
    next_action: "deepen_recon",
    recon_phase: "01-subdomain-enum",
  }, "example.com");
  assert.match(narrow.command, /recon-01 example\.com/);

  const cfg = loadBatchConfig({});
  const many = Array.from({ length: 30 }, (_, i) => `www.brand${i}.example`).join("\n");
  assert.equal(batchRequiredFromScope(many, 0, cfg, {}), true);
  assert.equal(batchRequiredFromScope("www.one.example\n", 1, cfg, {}), false);
  assert.equal(batchRequiredFromScope("www.one.example\n", 3, cfg, {}), true);
  assert.equal(batchRequiredFromScope("www.one.example\n", 58, cfg, {}), true);
  assert.equal(batchRequiredFromScope(many, 58, cfg, { BUGHIVE_BATCH: "0" }), false);
});

test("plan from a scope file spills a 58-host root without using the network", async () => {
  const dir = await mkdtemp(join(tmpdir(), "bh-tranche-"));
  const hosts = Array.from({ length: 58 }, (_, i) => `h${String(i).padStart(2, "0")}.root.example`);
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "scope.txt"), `${hosts.join("\n")}\n`);
  try {
    const plan = await buildPlan(dir, loadBatchConfig({}));
    assert.equal(plan.host_count, 58);
    assert.equal(plan.tranches.length, 58);
    assert.equal(plan.tranches[0].host_count, 1);
    assert.equal(plan.tranches[57].host_count, 1);
    assert.equal(plan.tranches[0].spilled, true);
    assert.ok(plan.ranked[0].host <= plan.ranked[1].host);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
