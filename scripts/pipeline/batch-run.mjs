/**
 * Bounded recon → proof-gated scan → findings, one tranche at a time.
 *
 *   node scripts/pipeline/batch-run.mjs plan <domain>
 *   node scripts/pipeline/batch-run.mjs step <domain>
 *   node scripts/pipeline/batch-run.mjs run <domain>
 *
 * Passive stages run across the whole in-scope set with per-host caps.
 * Active stages (crawl, port scan, nuclei) see only the current tranche's
 * hosts. The next tranche starts only after this tranche's findings file
 * has emitted. Proof gating stays inside `run.sh scan`.
 */

import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  advanceBatchState,
  initialBatchState,
  loadBatchConfig,
  nextBatchUnit,
  rankHosts,
  splitTranches,
  trancheMayAdvance,
} from "./tranche.mjs";
import { RECON_MAX_SECONDS } from "./jev-decide.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const HUNTS = join(ROOT, "hunts");

function sanitizeDomain(raw) {
  return String(raw || "")
    .trim()
    .replace(/^https?:\/\//, "")
    .split("/")[0]
    .split(":")[0]
    .toLowerCase();
}

function huntDir(domain) {
  return join(HUNTS, sanitizeDomain(domain));
}

async function readJson(path) {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch {
    return null;
  }
}

function linesOf(text) {
  return String(text || "")
    .split("\n")
    .map((line) => line.trim().toLowerCase().replace(/\.$/, ""))
    .filter((line) => line && !line.startsWith("#") && !line.startsWith("!"));
}

function literalHosts(scopeText) {
  const hosts = [];
  for (const line of linesOf(scopeText)) {
    for (const part of line.split(",")) {
      let host = part.trim().replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
      if (!host || host.includes("*")) continue;
      hosts.push(host);
    }
  }
  return [...new Set(hosts)];
}

function probeRows(summary) {
  const out = new Map();
  const results = summary?.results && typeof summary.results === "object" ? summary.results : {};
  for (const [host, rows] of Object.entries(results)) {
    const list = Array.isArray(rows) ? rows : [rows];
    const row = list.find((item) => item && typeof item === "object") || {};
    const tech = row.tech || row.technologies || row["tech-detect"] || [];
    out.set(String(host).toLowerCase(), {
      title: row.title || "",
      status: row.status_code ?? row.status ?? null,
      location: row.location || row["final-url"] || "",
      tech,
      webserver: row.webserver || row.webServer || "",
    });
  }
  return out;
}

function endpointCounts(text) {
  const counts = new Map();
  for (const line of String(text || "").split("\n")) {
    const raw = line.trim();
    if (!raw.startsWith("http")) continue;
    try {
      const host = new URL(raw).hostname.toLowerCase();
      counts.set(host, (counts.get(host) || 0) + 1);
    } catch {
      /* skip malformed */
    }
  }
  return counts;
}

export async function collectHostRows(hd) {
  const scopeText = existsSync(join(hd, "scope.txt")) ? readFileSync(join(hd, "scope.txt"), "utf8") : "";
  const assetsPath = join(hd, "recon", "01-subdomain-enum", "assets.txt");
  let hosts = [];
  if (existsSync(assetsPath)) {
    hosts = linesOf(readFileSync(assetsPath, "utf8"));
  }
  if (!hosts.length) hosts = literalHosts(scopeText);
  const probe = probeRows(await readJson(join(hd, "recon", "04-http-probe", "summary.json")));
  let endpoints = new Map();
  const endpointFile = join(hd, "recon", "all_endpoints");
  if (existsSync(endpointFile)) endpoints = endpointCounts(readFileSync(endpointFile, "utf8"));
  const urlFile = join(hd, "recon", "09-historical-data", "urls.txt");
  if (existsSync(urlFile)) {
    const extra = endpointCounts(readFileSync(urlFile, "utf8"));
    for (const [host, count] of extra) endpoints.set(host, (endpoints.get(host) || 0) + count);
  }
  return hosts.map((host) => ({
    host,
    ...(probe.get(host) || {}),
    endpointCount: endpoints.get(host) || 0,
  }));
}

export async function buildPlan(hd, config = loadBatchConfig()) {
  const rows = await collectHostRows(hd);
  const ranked = rankHosts(rows, config);
  const tranches = splitTranches(ranked, config);
  return {
    generated_at: new Date().toISOString(),
    batch_domains: config.batchDomains,
    tranche_host_cap: config.trancheHostCap,
    host_count: ranked.length,
    ranked: ranked.map((row) => ({
      host: row.host,
      registrable: row.registrable,
      score: row.score,
      tail: row.tail,
      reasons: row.reasons,
    })),
    tranches,
  };
}

async function writePlan(hd, plan) {
  const dir = join(hd, "batch");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "plan.json"), `${JSON.stringify(plan, null, 2)}\n`);
  for (const tranche of plan.tranches) {
    const tdir = join(dir, `tranche-${String(tranche.index).padStart(2, "0")}`);
    await mkdir(tdir, { recursive: true });
    await writeFile(join(tdir, "hosts.txt"), `${tranche.hosts.join("\n")}\n`);
  }
  return join(dir, "plan.json");
}

function reconElapsed(hd) {
  try {
    const raw = readFileSync(join(hd, ".state", "recon-elapsed-seconds"), "utf8").trim();
    const value = Number(raw);
    return Number.isFinite(value) ? value : 0;
  } catch {
    return 0;
  }
}

function reconBudget(env = process.env) {
  const raw = Number(env.BUGHIVE_RECON_MAX_SECONDS);
  return Number.isFinite(raw) && raw > 0 ? raw : RECON_MAX_SECONDS;
}

/** Tail tranches run only while accumulated recon time remains, unless forced. */
export function applyTailPolicy(plan, { elapsed, budget, includeTail }) {
  const next = {
    ...plan,
    tranches: plan.tranches.map((tranche) => ({ ...tranche })),
  };
  if (includeTail) return next;
  if (elapsed < budget) return next;
  for (const tranche of next.tranches) {
    if (tranche.tail) {
      tranche.skip = true;
      tranche.skip_reason = `tail tranche deferred; recon budget ${budget}s already used (${elapsed}s)`;
    }
  }
  return next;
}

function runCommand(command, { env, cwd }) {
  return new Promise((resolve) => {
    const child = spawn(command, { cwd, env, shell: true, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (buf) => {
      stdout += buf.toString();
    });
    child.stderr.on("data", (buf) => {
      stderr += buf.toString();
    });
    child.on("close", (code) => {
      resolve({ code: code ?? 1, stdout, stderr });
    });
  });
}

function stageEnv(base, config, extra = {}) {
  return {
    ...base,
    BUGHIVE_PASSIVE_WIDE: "1",
    BUGHIVE_GAU_MAX_ROOTS: "1000000",
    BUGHIVE_PORTSCAN_ENGINE: "naabu",
    ...extra,
  };
}

async function runPipeline(domain, stage, env) {
  const command = `bash scripts/pipeline/run.sh ${stage} ${sanitizeDomain(domain)}`;
  return runCommand(command, { cwd: ROOT, env });
}

function trancheDir(hd, index) {
  return join(hd, "batch", `tranche-${String(index).padStart(2, "0")}`);
}

async function readState(hd, done) {
  const path = join(hd, "batch", "state.json");
  const existing = await readJson(path);
  if (existing && existing.phase) return existing;
  return initialBatchState(done);
}

async function doneStages(hd) {
  try {
    const { readdir } = await import("node:fs/promises");
    const names = await readdir(join(hd, ".state"));
    return names.filter((name) => name.endsWith(".done")).map((name) => name.replace(/\.done$/, ""));
  } catch {
    return [];
  }
}

function pickBaseUrl(hd, hosts) {
  let summary = null;
  try {
    summary = JSON.parse(readFileSync(join(hd, "recon", "04-http-probe", "summary.json"), "utf8"));
  } catch {
    summary = null;
  }
  const wanted = new Set(hosts.map((host) => host.toLowerCase()));
  const results = summary?.results || {};
  for (const host of hosts) {
    const rows = results[host] || results[host.toLowerCase()] || [];
    const list = Array.isArray(rows) ? rows : [rows];
    const url = list.map((row) => row?.url).find((url) => typeof url === "string" && url.startsWith("http"));
    if (url) return url;
  }
  for (const [host, rows] of Object.entries(results)) {
    if (!wanted.has(String(host).toLowerCase())) continue;
    const list = Array.isArray(rows) ? rows : [rows];
    const url = list.map((row) => row?.url).find((url) => typeof url === "string" && url.startsWith("http"));
    if (url) return url;
  }
  if (hosts[0]) return `https://${hosts[0]}`;
  return "";
}

function dedupeRecords(items) {
  const seen = new Set();
  const out = [];
  for (const item of items || []) {
    const key = item && item.id ? String(item.id) : JSON.stringify(item);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

async function emitFindings(hd, tranche, { skipped = false, scanCode = 0, note = "", truncated = false } = {}) {
  const dir = trancheDir(hd, tranche.index);
  await mkdir(dir, { recursive: true });
  const findings = (await readJson(join(dir, "scan-findings.json")))
    || (skipped ? [] : await readJson(join(hd, "findings.json")))
    || [];
  const validated = (await readJson(join(dir, "scan-validated.json")))
    || (skipped ? [] : await readJson(join(hd, "validated.json")))
    || [];
  const record = {
    tranche: tranche.index,
    emitted: true,
    emitted_at: new Date().toISOString(),
    skipped: Boolean(skipped),
    degraded: Boolean(skipped || scanCode !== 0 || truncated),
    truncated: Boolean(truncated),
    findings: Array.isArray(findings) ? findings : [],
    validated: Array.isArray(validated) ? validated : [],
    notes: [
      skipped
        ? tranche.skip_reason || "tranche skipped"
        : "findings copied from the proof-gated scan output",
      note,
    ].filter(Boolean),
  };
  if (!trancheMayAdvance(record)) record.emitted = true;
  await writeFile(join(dir, "findings.json"), `${JSON.stringify(record, null, 2)}\n`);
  return record;
}

async function mergeBatchFindings(hd, plan) {
  const all = [];
  const validated = [];
  for (const tranche of plan.tranches) {
    const record = await readJson(join(trancheDir(hd, tranche.index), "findings.json"));
    if (!record) continue;
    for (const finding of record.findings || []) all.push({ ...finding, tranche: tranche.index });
    for (const finding of record.validated || []) validated.push({ ...finding, tranche: tranche.index });
  }
  await mkdir(join(hd, "batch"), { recursive: true });
  await writeFile(join(hd, "batch", "findings.json"), `${JSON.stringify(all, null, 2)}\n`);
  await writeFile(join(hd, "findings.json"), `${JSON.stringify(all, null, 2)}\n`);
  await writeFile(join(hd, "validated.json"), `${JSON.stringify(validated, null, 2)}\n`);
}

export async function stepDomain(domain, env = process.env) {
  const hd = huntDir(domain);
  if (!existsSync(join(hd, "scope.txt"))) {
    throw new Error(`no scope.txt under ${hd}; run init first`);
  }
  const config = loadBatchConfig(env);
  let plan = await readJson(join(hd, "batch", "plan.json"));
  if (!plan) {
    plan = await buildPlan(hd, config);
    await writePlan(hd, plan);
  }
  const done = await doneStages(hd);
  let state = await readState(hd, done);
  plan = applyTailPolicy(plan, {
    elapsed: reconElapsed(hd),
    budget: reconBudget(env),
    includeTail: config.includeTail === 1,
  });
  const unit = nextBatchUnit(state, plan);
  const report = { unit: unit.kind, stage: unit.stage || null, tranche: unit.tranche || null, code: 0 };

  if (unit.kind === "done") {
    state = { ...state, phase: "done", complete: true };
    await writeFile(join(hd, "batch", "state.json"), `${JSON.stringify(state, null, 2)}\n`);
    report.complete = true;
    return report;
  }

  if (unit.kind === "passive") {
    const extra = {};
    if (unit.stage === "recon-07") {
      const raised = config.jsFetchTotal > 0
        ? config.jsFetchTotal
        : config.trancheHostCap * config.jsFetchCap;
      extra.BUGHIVE_JS_FETCH_TOTAL = String(raised);
    }
    const result = await runPipeline(domain, unit.stage, stageEnv(env, config, extra));
    report.code = result.code;
    report.stderr_tail = result.stderr.slice(-500);
    if (result.code !== 0) return report;
  } else if (unit.kind === "rank") {
    plan = await buildPlan(hd, config);
    plan = applyTailPolicy(plan, {
      elapsed: reconElapsed(hd),
      budget: reconBudget(env),
      includeTail: config.includeTail === 1,
    });
    await writePlan(hd, plan);
    report.tranches = plan.tranches.length;
    report.hosts = plan.host_count;
  } else if (unit.kind === "active") {
    const tranche = plan.tranches[(state.tranche_index || 0)];
    const hostFile = join(trancheDir(hd, tranche.index), "hosts.txt");
    const result = await runPipeline(domain, unit.stage, stageEnv(env, config, {
      BUGHIVE_TRANCHE_HOSTS: hostFile,
      BUGHIVE_PORTSCAN_ENGINE: "naabu",
    }));
    report.code = result.code;
    report.stderr_tail = result.stderr.slice(-500);
    if (result.code !== 0) return report;
  } else if (unit.kind === "scan") {
    const tranche = plan.tranches[state.tranche_index || 0];
    const started = Date.now();
    const budgetMs = config.trancheScanBudgetSeconds * 1000;
    const mergedFindings = [];
    const mergedValidated = [];
    let scannedHosts = 0;
    let lastCode = 0;
    let timedOut = false;
    for (const host of tranche.hosts) {
      const elapsed = Date.now() - started;
      if (elapsed >= budgetMs) {
        timedOut = true;
        break;
      }
      const base = pickBaseUrl(hd, [host]);
      if (!base) continue;
      const left = Math.max(5, Math.ceil((budgetMs - elapsed) / 1000));
      const result = await runCommand(
        `timeout ${left} bash scripts/pipeline/run.sh scan ${sanitizeDomain(domain)} ${JSON.stringify(base)}`,
        { cwd: ROOT, env: stageEnv(env, config) },
      );
      lastCode = result.code;
      scannedHosts += 1;
      if (result.code === 124) timedOut = true;
      const found = await readJson(join(hd, "findings.json"));
      const validated = await readJson(join(hd, "validated.json"));
      if (Array.isArray(found)) mergedFindings.push(...found);
      if (Array.isArray(validated)) mergedValidated.push(...validated);
      if (timedOut) break;
    }
    const findings = dedupeRecords(mergedFindings);
    const validated = dedupeRecords(mergedValidated);
    const dir = trancheDir(hd, tranche.index);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "scan-findings.json"), `${JSON.stringify(findings, null, 2)}\n`);
    await writeFile(join(dir, "scan-validated.json"), `${JSON.stringify(validated, null, 2)}\n`);
    report.scanned_hosts = scannedHosts;
    report.scan_code = lastCode;
    report.code = 0;
    report.elapsed_ms = Date.now() - started;
    state.last_scan_code = lastCode;
    state.scan_truncated = timedOut || scannedHosts < tranche.hosts.length;
    if (state.scan_truncated) report.truncated = true;
    if (!scannedHosts) report.note = "no live URL in tranche; proof-gated scan was not started";
    else if (lastCode !== 0) {
      report.note = "proof-gated scan exited non-zero; partial findings still emit so the tranche can finish";
    }
  } else if (unit.kind === "emit") {
    const tranche = plan.tranches[state.tranche_index || 0];
    const record = await emitFindings(hd, tranche, {
      skipped: Boolean(unit.skipped || tranche.skip),
      scanCode: state.last_scan_code || 0,
      truncated: Boolean(state.scan_truncated || tranche.skip),
      note: state.last_scan_code ? "scan exit was non-zero" : "",
    });
    report.emitted = record.emitted;
    report.finding_count = record.findings.length;
  } else if (unit.kind === "advance") {
    const emitted = await readJson(join(
      trancheDir(hd, plan.tranches[state.tranche_index || 0].index),
      "findings.json",
    ));
    if (!trancheMayAdvance(emitted)) {
      report.code = 1;
      report.note = "refusing to start the next tranche before findings emit";
      return report;
    }
  }

  if (report.code !== 0 && unit.kind !== "scan") return report;
  state = advanceBatchState(state, unit, { trancheCount: plan.tranches.length });
  if (unit.kind === "emit" || state.complete) await mergeBatchFindings(hd, plan);
  await mkdir(join(hd, "batch"), { recursive: true });
  await writeFile(join(hd, "batch", "state.json"), `${JSON.stringify(state, null, 2)}\n`);
  report.complete = state.complete;
  report.phase = state.phase;
  return report;
}

async function main() {
  const cmd = process.argv[2];
  const domain = process.argv[3];
  if (!cmd || !domain || !["plan", "step", "run"].includes(cmd)) {
    process.stderr.write("usage: batch-run.mjs <plan|step|run> <domain>\n");
    process.exit(2);
  }
  if (cmd === "plan") {
    const hd = huntDir(domain);
    const plan = await buildPlan(hd, loadBatchConfig());
    const path = await writePlan(hd, plan);
    process.stdout.write(`${JSON.stringify({
      plan: path,
      hosts: plan.host_count,
      tranches: plan.tranches.length,
      tranche_hosts: plan.tranches.map((t) => t.host_count),
    })}\n`);
    return;
  }
  if (cmd === "step") {
    const report = await stepDomain(domain);
    process.stdout.write(`${JSON.stringify(report)}\n`);
    if (report.code) process.exitCode = report.code;
    return;
  }
  const config = loadBatchConfig();
  const reports = [];
  for (let i = 0; i < config.maxSteps; i += 1) {
    const report = await stepDomain(domain);
    reports.push({ unit: report.unit, stage: report.stage, tranche: report.tranche, code: report.code, complete: report.complete });
    if (report.code) {
      process.stdout.write(`${JSON.stringify({ steps: reports, failed: report })}\n`);
      process.exitCode = report.code;
      return;
    }
    if (report.complete || report.unit === "done") break;
  }
  process.stdout.write(`${JSON.stringify({ steps: reports })}\n`);
}

const invoked = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invoked) {
  main().catch((err) => {
    process.stderr.write(`${err?.stack || err}\n`);
    process.exitCode = 1;
  });
}
