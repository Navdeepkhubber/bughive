/**
 * Multi-domain tranche planner.
 *
 * Cost follows live-host count, so a domains-per-batch knob still stops at
 * BUGHIVE_TRANCHE_HOST_CAP and spills the rest. Ranking is a pure sort.
 * Stage bounds keep partial results and set degraded/truncated instead of
 * blocking the next stage. Defaults live in data/batch-defaults.json.
 *
 *   node scripts/pipeline/tranche.mjs config
 *   node scripts/pipeline/tranche.mjs order-hosts   # hosts on stdin
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { registrableDomain } from "../../plugins/dsh-scope-intake/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULTS_PATH = join(HERE, "data", "batch-defaults.json");

export const PASSIVE_STAGES = ["recon-01", "recon-02", "recon-04", "recon-09", "recon-07"];
export const ACTIVE_STAGES = ["recon-05", "recon-03", "recon-14"];

let cachedDefaults;

export function batchDefaults() {
  if (!cachedDefaults) {
    const raw = JSON.parse(readFileSync(DEFAULTS_PATH, "utf8"));
    cachedDefaults = Object.fromEntries(Object.entries(raw).filter(([key]) => key !== "note"));
  }
  return cachedDefaults;
}

function csv(value) {
  return String(value ?? "")
    .split(",")
    .map((part) => part.trim().toLowerCase())
    .filter(Boolean);
}

function intKnob(env, name, fallback, { min = null, max = null } = {}) {
  const raw = env[name];
  const source = raw != null && String(raw) !== "" ? raw : fallback;
  let value = Number(source);
  if (!Number.isFinite(value)) value = Number(fallback);
  value = Math.trunc(value);
  if (min != null) value = Math.max(min, value);
  if (max != null) value = Math.min(max, value);
  return value;
}

function strKnob(env, name, fallback) {
  const raw = env[name];
  if (raw != null && String(raw) !== "") return String(raw);
  return fallback == null ? "" : String(fallback);
}

/** Resolved knobs. `env` defaults to process.env so tests can pass a fake map. */
export function loadBatchConfig(env = process.env) {
  const d = batchDefaults();
  const cfg = {
    batchDomains: intKnob(env, "BUGHIVE_BATCH_DOMAINS", d.BUGHIVE_BATCH_DOMAINS, { min: 1 }),
    trancheHostCap: intKnob(env, "BUGHIVE_TRANCHE_HOST_CAP", d.BUGHIVE_TRANCHE_HOST_CAP, { min: 1 }),
    passiveUrlCap: intKnob(env, "BUGHIVE_PASSIVE_URL_CAP", d.BUGHIVE_PASSIVE_URL_CAP, { min: 1 }),
    jsFetchCap: intKnob(env, "BUGHIVE_JS_FETCH_CAP", d.BUGHIVE_JS_FETCH_CAP, { min: 1 }),
    jsFetchTotal: intKnob(env, "BUGHIVE_JS_FETCH_TOTAL", d.BUGHIVE_JS_FETCH_TOTAL, { min: 0 }),
    jsBudgetSeconds: intKnob(env, "BUGHIVE_JS_BUDGET_SECONDS", d.BUGHIVE_JS_BUDGET_SECONDS, { min: 1 }),
    rankFloor: intKnob(env, "BUGHIVE_HOST_RANK_FLOOR", d.BUGHIVE_HOST_RANK_FLOOR),
    includeTail: intKnob(env, "BUGHIVE_TRANCHE_INCLUDE_TAIL", d.BUGHIVE_TRANCHE_INCLUDE_TAIL, { min: 0, max: 1 }),
    endpointSignalMin: intKnob(env, "BUGHIVE_ENDPOINT_SIGNAL_MIN", d.BUGHIVE_ENDPOINT_SIGNAL_MIN, { min: 1 }),
    weights: {
      appKeyword: intKnob(env, "BUGHIVE_WEIGHT_APP_KEYWORD", d.BUGHIVE_WEIGHT_APP_KEYWORD),
      login: intKnob(env, "BUGHIVE_WEIGHT_LOGIN", d.BUGHIVE_WEIGHT_LOGIN),
      tech: intKnob(env, "BUGHIVE_WEIGHT_TECH", d.BUGHIVE_WEIGHT_TECH),
      endpoints: intKnob(env, "BUGHIVE_WEIGHT_ENDPOINTS", d.BUGHIVE_WEIGHT_ENDPOINTS),
      appStatus: intKnob(env, "BUGHIVE_WEIGHT_APP_STATUS", d.BUGHIVE_WEIGHT_APP_STATUS),
      lowKeyword: intKnob(env, "BUGHIVE_WEIGHT_LOW_KEYWORD", d.BUGHIVE_WEIGHT_LOW_KEYWORD),
      cdn: intKnob(env, "BUGHIVE_WEIGHT_CDN", d.BUGHIVE_WEIGHT_CDN),
    },
    appKeywords: csv(strKnob(env, "BUGHIVE_APP_KEYWORDS", d.BUGHIVE_APP_KEYWORDS)),
    lowKeywords: csv(strKnob(env, "BUGHIVE_LOW_KEYWORDS", d.BUGHIVE_LOW_KEYWORDS)),
    appTech: csv(strKnob(env, "BUGHIVE_APP_TECH", d.BUGHIVE_APP_TECH)),
    edgeTech: csv(strKnob(env, "BUGHIVE_EDGE_TECH", d.BUGHIVE_EDGE_TECH)),
    httpx: {
      threads: intKnob(env, "BUGHIVE_HTTPX_THREADS", d.BUGHIVE_HTTPX_THREADS, { min: 1 }),
      rateLimit: intKnob(env, "BUGHIVE_HTTPX_RATE", d.BUGHIVE_HTTPX_RATE, { min: 1 }),
      budgetSeconds: intKnob(env, "BUGHIVE_HTTPX_BUDGET_SECONDS", d.BUGHIVE_HTTPX_BUDGET_SECONDS, { min: 1 }),
      resultCap: intKnob(env, "BUGHIVE_HTTPX_RESULT_CAP", d.BUGHIVE_HTTPX_RESULT_CAP, { min: 1 }),
      techDetect: intKnob(env, "BUGHIVE_HTTPX_TECH_DETECT", d.BUGHIVE_HTTPX_TECH_DETECT, { min: 0, max: 1 }),
    },
    katana: {
      concurrency: intKnob(env, "BUGHIVE_KATANA_CONCURRENCY", d.BUGHIVE_KATANA_CONCURRENCY, { min: 1 }),
      parallelism: intKnob(env, "BUGHIVE_KATANA_PARALLELISM", d.BUGHIVE_KATANA_PARALLELISM, { min: 1 }),
      rateLimit: intKnob(env, "BUGHIVE_KATANA_RATE", d.BUGHIVE_KATANA_RATE, { min: 1 }),
      depth: intKnob(env, "BUGHIVE_KATANA_DEPTH", d.BUGHIVE_KATANA_DEPTH, { min: 1 }),
      hostRateLimit: intKnob(env, "BUGHIVE_KATANA_HOST_RATE", d.BUGHIVE_KATANA_HOST_RATE, { min: 1 }),
      perHostSeconds: intKnob(env, "BUGHIVE_KATANA_PER_HOST_SECONDS", d.BUGHIVE_KATANA_PER_HOST_SECONDS, { min: 1 }),
      budgetSeconds: intKnob(env, "BUGHIVE_KATANA_BUDGET_SECONDS", d.BUGHIVE_KATANA_BUDGET_SECONDS, { min: 1 }),
      resultCap: intKnob(env, "BUGHIVE_KATANA_RESULT_CAP", d.BUGHIVE_KATANA_RESULT_CAP, { min: 1 }),
    },
    portscanEngine: strKnob(env, "BUGHIVE_PORTSCAN_ENGINE", d.BUGHIVE_PORTSCAN_ENGINE).toLowerCase(),
    naabu: {
      scanType: strKnob(env, "BUGHIVE_NAABU_SCAN", d.BUGHIVE_NAABU_SCAN),
      rate: intKnob(env, "BUGHIVE_NAABU_RATE", d.BUGHIVE_NAABU_RATE, { min: 1 }),
      concurrency: intKnob(env, "BUGHIVE_NAABU_CONCURRENCY", d.BUGHIVE_NAABU_CONCURRENCY, { min: 1 }),
      retries: intKnob(env, "BUGHIVE_NAABU_RETRIES", d.BUGHIVE_NAABU_RETRIES, { min: 0 }),
      topPorts: intKnob(env, "BUGHIVE_NAABU_TOP_PORTS", d.BUGHIVE_NAABU_TOP_PORTS, { min: 1 }),
      budgetSeconds: intKnob(env, "BUGHIVE_NAABU_BUDGET_SECONDS", d.BUGHIVE_NAABU_BUDGET_SECONDS, { min: 1 }),
      resultCap: intKnob(env, "BUGHIVE_NAABU_RESULT_CAP", d.BUGHIVE_NAABU_RESULT_CAP, { min: 1 }),
    },
    nuclei: {
      rateLimit: intKnob(env, "BUGHIVE_NUCLEI_RATE", d.BUGHIVE_NUCLEI_RATE, { min: 1 }),
      concurrency: intKnob(env, "BUGHIVE_NUCLEI_CONCURRENCY", d.BUGHIVE_NUCLEI_CONCURRENCY, { min: 1 }),
      bulkSize: intKnob(env, "BUGHIVE_NUCLEI_BULK", d.BUGHIVE_NUCLEI_BULK, { min: 1 }),
      severityFirst: strKnob(env, "BUGHIVE_NUCLEI_SEVERITY_FIRST", d.BUGHIVE_NUCLEI_SEVERITY_FIRST),
      severityRest: strKnob(env, "BUGHIVE_NUCLEI_SEVERITY_REST", d.BUGHIVE_NUCLEI_SEVERITY_REST),
      budgetSeconds: intKnob(env, "BUGHIVE_NUCLEI_BUDGET_SECONDS", d.BUGHIVE_NUCLEI_BUDGET_SECONDS, { min: 1 }),
      resultCap: intKnob(env, "BUGHIVE_NUCLEI_RESULT_CAP", d.BUGHIVE_NUCLEI_RESULT_CAP, { min: 1 }),
    },
    gau: {
      threads: intKnob(env, "BUGHIVE_GAU_THREADS", d.BUGHIVE_GAU_THREADS, { min: 1 }),
      budgetSeconds: intKnob(env, "BUGHIVE_GAU_BUDGET_SECONDS", d.BUGHIVE_GAU_BUDGET_SECONDS, { min: 1 }),
      providers: strKnob(env, "BUGHIVE_GAU_PROVIDERS", d.BUGHIVE_GAU_PROVIDERS),
      blacklist: strKnob(env, "BUGHIVE_GAU_BLACKLIST", d.BUGHIVE_GAU_BLACKLIST),
    },
    subfinderBudgetSeconds: intKnob(env, "BUGHIVE_SUBFINDER_BUDGET_SECONDS", d.BUGHIVE_SUBFINDER_BUDGET_SECONDS, { min: 1 }),
    subfinderPerRootSeconds: intKnob(env, "BUGHIVE_SUBFINDER_PER_ROOT_SECONDS", d.BUGHIVE_SUBFINDER_PER_ROOT_SECONDS, { min: 1 }),
    amassPerRootSeconds: intKnob(env, "BUGHIVE_AMASS_PER_ROOT_SECONDS", d.BUGHIVE_AMASS_PER_ROOT_SECONDS, { min: 1 }),
    dnsBudgetSeconds: intKnob(env, "BUGHIVE_DNS_BUDGET_SECONDS", d.BUGHIVE_DNS_BUDGET_SECONDS, { min: 1 }),
    dnsPerQuerySeconds: intKnob(env, "BUGHIVE_DNS_PER_QUERY_SECONDS", d.BUGHIVE_DNS_PER_QUERY_SECONDS, { min: 1 }),
    trancheScanBudgetSeconds: intKnob(env, "BUGHIVE_TRANCHE_SCAN_BUDGET_SECONDS", d.BUGHIVE_TRANCHE_SCAN_BUDGET_SECONDS, { min: 1 }),
    maxSteps: intKnob(env, "BUGHIVE_BATCH_MAX_STEPS", d.BUGHIVE_BATCH_MAX_STEPS, { min: 1 }),
  };
  return cfg;
}

export function hostTokens(host) {
  return String(host || "")
    .toLowerCase()
    .split(/[.\-_]+/)
    .filter(Boolean);
}

/** Keyword matches a DNS label or the start of one (`book` → `booking`). */
export function keywordHit(host, keyword) {
  const kw = String(keyword || "").toLowerCase();
  if (!kw) return false;
  return hostTokens(host).some((token) => token === kw || token.startsWith(kw));
}

function asList(value) {
  if (Array.isArray(value)) return value.map((v) => String(v));
  if (value == null || value === "") return [];
  return String(value).split(/[,;/|]/).map((v) => v.trim()).filter(Boolean);
}

function loginDetected(row) {
  const title = String(row.title || "").toLowerCase();
  const location = String(row.location || "").toLowerCase();
  if (/login|sign[\s-]?in|sso|oauth/.test(title)) return true;
  if (/\/(login|signin|sign-in|sso|oauth|auth)\b/.test(location)) return true;
  const status = Number(row.status);
  if ([301, 302, 303, 307, 308].includes(status) && /login|signin|sso|oauth|auth/.test(location)) return true;
  return false;
}

function techBlob(row) {
  return asList(row.tech).concat(asList(row.webserver)).join(" ").toLowerCase();
}

/**
 * Score one live host. `row` may be `{ host }` alone. Higher is more interesting.
 * Returns `{ host, registrable, score, tail, reasons }`.
 */
export function scoreHost(row, config = loadBatchConfig()) {
  const host = String(row?.host || "").trim().toLowerCase().replace(/\.$/, "");
  const reasons = [];
  let score = 0;
  const weights = config.weights;
  for (const kw of config.appKeywords) {
    if (keywordHit(host, kw)) {
      score += weights.appKeyword;
      reasons.push(`app:${kw}+${weights.appKeyword}`);
    }
  }
  if (loginDetected(row)) {
    score += weights.login;
    reasons.push(`login+${weights.login}`);
  }
  const blob = techBlob(row);
  const edge = config.edgeTech.some((name) => blob.includes(name));
  const appTech = config.appTech.some((name) => blob.includes(name));
  if (appTech) {
    score += weights.tech;
    reasons.push(`tech+${weights.tech}`);
  }
  const endpoints = Number(row.endpointCount || 0);
  if (Number.isFinite(endpoints) && endpoints >= config.endpointSignalMin) {
    score += weights.endpoints;
    reasons.push(`endpoints+${weights.endpoints}`);
  }
  const status = Number(row.status);
  const appLooking = reasons.some((r) => r.startsWith("app:") || r.startsWith("tech+") || r.startsWith("login+"));
  if (appLooking && [200, 401, 403].includes(status)) {
    score += weights.appStatus;
    reasons.push(`status+${weights.appStatus}`);
  }
  for (const kw of config.lowKeywords) {
    if (keywordHit(host, kw)) {
      score -= weights.lowKeyword;
      reasons.push(`low:${kw}-${weights.lowKeyword}`);
    }
  }
  if (edge || row.cdn === true || row.wildcardStatic === true) {
    score -= weights.cdn;
    reasons.push(`cdn-${weights.cdn}`);
  }
  const registrable = registrableDomain(host) || host;
  return {
    host,
    registrable,
    score,
    tail: score < config.rankFloor,
    reasons,
  };
}

function byRank(a, b) {
  if (a.tail !== b.tail) return a.tail ? 1 : -1;
  if (b.score !== a.score) return b.score - a.score;
  if (a.host < b.host) return -1;
  if (a.host > b.host) return 1;
  return 0;
}

/** Deterministic: score descending, hostname ascending, primary before tail. */
export function rankHosts(rows, config = loadBatchConfig()) {
  return (rows || []).map((row) => scoreHost(row, config)).filter((row) => row.host).sort(byRank);
}

function emptyTranche() {
  return { domains: [], hosts: [], tail: true, domainSet: new Set() };
}

function packChunks(chunks, { batchDomains, hostCap }) {
  const tranches = [];
  let current = emptyTranche();
  const flush = () => {
    if (!current.hosts.length) return;
    tranches.push({
      domains: current.domains.slice(),
      hosts: current.hosts.slice(),
      tail: current.tail,
    });
    current = emptyTranche();
  };
  const pushHost = (domain, host, tail) => {
    current.hosts.push(host);
    if (!current.domainSet.has(domain)) {
      current.domainSet.add(domain);
      current.domains.push(domain);
    }
    if (!tail) current.tail = false;
    if (current.hosts.length >= hostCap) flush();
  };
  for (const chunk of chunks) {
    let pending = chunk.hosts.slice();
    if (chunk.tail && current.hosts.length && current.tail === false) flush();
    while (pending.length) {
      const domainNew = !current.domainSet.has(chunk.domain);
      const overDomains = current.hosts.length > 0 && domainNew && current.domainSet.size >= batchDomains;
      if (overDomains) flush();
      const room = hostCap - current.hosts.length;
      if (!Number.isFinite(room) || room <= 0) {
        if (!current.hosts.length) break;
        flush();
        continue;
      }
      const take = pending.slice(0, room);
      pending = pending.slice(room);
      for (const host of take) pushHost(chunk.domain, host.host, chunk.tail);
    }
  }
  flush();
  const domainTranches = new Map();
  for (const tranche of tranches) {
    for (const domain of tranche.domains) {
      domainTranches.set(domain, (domainTranches.get(domain) || 0) + 1);
    }
  }
  return tranches.map((tranche, index) => ({
    index: index + 1,
    domains: tranche.domains,
    hosts: tranche.hosts,
    host_count: tranche.hosts.length,
    tail: tranche.tail,
    spilled: tranche.domains.some((domain) => (domainTranches.get(domain) || 0) > 1),
  }));
}

/**
 * Split ranked hosts into tranches.
 *
 * Domains are packed in rank order, but a tranche never holds more than
 * `trancheHostCap` hosts. A single registrable domain larger than the cap
 * spills into the next tranche instead of blowing the batch open.
 * Tail hosts (below the rank floor) are packed after every primary host.
 */
export function splitTranches(rows, config = loadBatchConfig()) {
  const ranked = Array.isArray(rows) && rows.length && rows[0] && rows[0].registrable && "score" in rows[0]
    ? rows.slice().sort(byRank)
    : rankHosts(rows, config);
  const groups = new Map();
  for (const row of ranked) {
    const key = `${row.tail ? "t" : "p"}:${row.registrable}`;
    if (!groups.has(key)) {
      groups.set(key, { domain: row.registrable, tail: row.tail, hosts: [], best: row.score });
    }
    const group = groups.get(key);
    group.hosts.push(row);
    if (row.score > group.best) group.best = row.score;
  }
  const chunks = [...groups.values()].sort((a, b) => {
    if (a.tail !== b.tail) return a.tail ? 1 : -1;
    if (b.best !== a.best) return b.best - a.best;
    if (a.domain < b.domain) return -1;
    if (a.domain > b.domain) return 1;
    return 0;
  });
  return packChunks(chunks, {
    batchDomains: config.batchDomains,
    hostCap: config.trancheHostCap,
  });
}

/**
 * Whichever bound hits first wins. Partial rows are returned either way.
 * `degraded` and `truncated` are true when the stage did not finish cleanly.
 */
export function applyStageBounds({ results = [], resultCap = null, elapsedMs = null, budgetMs = null, exitCode = null } = {}) {
  const rows = Array.isArray(results) ? results.slice() : [];
  const total = rows.length;
  const reasons = [];
  let truncated = false;
  let kept = rows;
  const cap = resultCap == null || resultCap === "" ? null : Number(resultCap);
  if (Number.isFinite(cap) && cap >= 0 && total > cap) {
    kept = rows.slice(0, cap);
    truncated = true;
    reasons.push(`result cap ${cap} reached; kept ${cap} of ${total}`);
  }
  const timedOut = Number(exitCode) === 124;
  const budget = budgetMs == null || budgetMs === "" ? null : Number(budgetMs);
  const elapsed = elapsedMs == null || elapsedMs === "" ? null : Number(elapsedMs);
  const overBudget = Number.isFinite(budget) && budget > 0 && Number.isFinite(elapsed) && elapsed >= budget;
  if (timedOut || overBudget) {
    truncated = true;
    reasons.push(
      timedOut
        ? "wall-clock budget expired (exit 124); partial results kept"
        : `wall-clock budget ${Math.trunc(budget)}ms exceeded at ${Math.trunc(elapsed)}ms; partial results kept`,
    );
  }
  return {
    results: kept,
    count: kept.length,
    count_total: total,
    degraded: truncated,
    truncated,
    reasons,
  };
}

export function trancheMayAdvance(record) {
  return record?.emitted === true || record?.findings?.emitted === true;
}

/** argv for the expensive tools. Phases pass the same flags the brief names. */
export function stageArgs(stage, config = loadBatchConfig()) {
  if (stage === "httpx") {
    const args = ["httpx", "-t", String(config.httpx.threads), "-rl", String(config.httpx.rateLimit)];
    if (config.httpx.techDetect) args.push("-tech-detect");
    return args;
  }
  if (stage === "katana") {
    return [
      "katana",
      "-c", String(config.katana.concurrency),
      "-p", String(config.katana.parallelism),
      "-rl", String(config.katana.rateLimit),
      "-d", String(config.katana.depth),
      "-hrl", String(config.katana.hostRateLimit),
    ];
  }
  if (stage === "naabu") {
    return [
      "naabu",
      "-s", String(config.naabu.scanType),
      "-rate", String(config.naabu.rate),
      "-c", String(config.naabu.concurrency),
      "-retries", String(config.naabu.retries),
      "-top-ports", String(config.naabu.topPorts),
    ];
  }
  if (stage === "nuclei") {
    return [
      "nuclei",
      "-rl", String(config.nuclei.rateLimit),
      "-c", String(config.nuclei.concurrency),
      "-bs", String(config.nuclei.bulkSize),
      "-severity", String(config.nuclei.severityFirst),
    ];
  }
  if (stage === "gau") {
    return [
      "gau",
      "--subs",
      "--threads", String(config.gau.threads),
      "--providers", String(config.gau.providers),
      "--blacklist", String(config.gau.blacklist),
    ];
  }
  return [];
}

export function stageBudget(stage, config = loadBatchConfig()) {
  const table = {
    httpx: { budgetSeconds: config.httpx.budgetSeconds, resultCap: config.httpx.resultCap },
    katana: { budgetSeconds: config.katana.budgetSeconds, resultCap: config.katana.resultCap, perHostSeconds: config.katana.perHostSeconds },
    naabu: { budgetSeconds: config.naabu.budgetSeconds, resultCap: config.naabu.resultCap },
    nuclei: { budgetSeconds: config.nuclei.budgetSeconds, resultCap: config.nuclei.resultCap },
    gau: { budgetSeconds: config.gau.budgetSeconds, resultCap: config.passiveUrlCap },
    js: { budgetSeconds: config.jsBudgetSeconds, resultCap: config.jsFetchCap },
  };
  return table[stage] || null;
}

function scopeTokens(scopeText) {
  const regs = new Set();
  let literals = 0;
  for (const rawLine of String(scopeText || "").split("\n")) {
    const line = rawLine.split("#")[0].trim().toLowerCase();
    if (!line || line.startsWith("!")) continue;
    for (const part of line.split(",")) {
      let host = part.trim().replace(/^https?:\/\//, "").split("/")[0].split(":")[0].replace(/\.$/, "");
      if (!host) continue;
      const wild = host.includes("*");
      const concrete = host.replace(/\*/g, "").replace(/^\.+/, "").replace(/\.+$/, "");
      const reg = registrableDomain(wild ? concrete : host);
      if (reg) regs.add(reg);
      if (!wild) literals += 1;
    }
  }
  return { registrable: regs.size, literals };
}

/**
 * Auto-on when the scope is wider than one tranche. BUGHIVE_BATCH=0 forces off,
 * BUGHIVE_BATCH=1 forces on. Host count, not domain count, is enough by itself.
 */
export function batchRequiredFromScope(scopeText, discoveredCount, config = loadBatchConfig(), env = process.env) {
  const flag = String(env.BUGHIVE_BATCH ?? "").trim().toLowerCase();
  if (["0", "off", "false", "no"].includes(flag)) return false;
  if (["1", "on", "true", "yes"].includes(flag)) return true;
  const stats = scopeTokens(scopeText);
  if (stats.registrable > config.batchDomains) return true;
  if (stats.literals > config.trancheHostCap) return true;
  if (Number(discoveredCount) > config.trancheHostCap) return true;
  return false;
}

export function initialBatchState(doneStages = []) {
  const done = new Set(doneStages);
  let passiveIndex = 0;
  while (passiveIndex < PASSIVE_STAGES.length && done.has(PASSIVE_STAGES[passiveIndex])) {
    passiveIndex += 1;
  }
  if (passiveIndex >= PASSIVE_STAGES.length) {
    return {
      phase: "rank",
      passive_index: passiveIndex,
      tranche_index: 0,
      active_index: 0,
      scanned: false,
      findings_emitted: false,
      complete: false,
    };
  }
  return {
    phase: "passive",
    passive_index: passiveIndex,
    tranche_index: 0,
    active_index: 0,
    scanned: false,
    findings_emitted: false,
    complete: false,
  };
}

/** The next bounded unit. The tranche does not advance until findings emitted. */
export function nextBatchUnit(state, plan) {
  const st = state || initialBatchState();
  if (st.complete || st.phase === "done") return { kind: "done" };
  if (!st.phase || st.phase === "passive") {
    const index = st.passive_index || 0;
    if (index < PASSIVE_STAGES.length) {
      return { kind: "passive", stage: PASSIVE_STAGES[index], index };
    }
    return { kind: "rank" };
  }
  if (st.phase === "rank") return { kind: "rank" };
  const tranches = plan?.tranches || [];
  const tranche = tranches[st.tranche_index || 0];
  if (!tranche) return { kind: "done" };
  if (tranche.tail && tranche.skip) {
    if (!st.findings_emitted) return { kind: "emit", tranche: tranche.index, skipped: true };
    return { kind: "advance", tranche: tranche.index };
  }
  const activeIndex = st.active_index || 0;
  if (activeIndex < ACTIVE_STAGES.length) {
    return { kind: "active", stage: ACTIVE_STAGES[activeIndex], tranche: tranche.index, index: activeIndex };
  }
  if (!st.scanned) return { kind: "scan", tranche: tranche.index };
  if (!st.findings_emitted) return { kind: "emit", tranche: tranche.index };
  return { kind: "advance", tranche: tranche.index };
}

export function advanceBatchState(state, unit, { trancheCount = 0 } = {}) {
  const st = { ...(state || initialBatchState()) };
  if (unit.kind === "passive") {
    st.phase = "passive";
    st.passive_index = (st.passive_index || 0) + 1;
    if (st.passive_index >= PASSIVE_STAGES.length) st.phase = "rank";
  } else if (unit.kind === "rank") {
    st.phase = "tranche";
    st.tranche_index = 0;
    st.active_index = 0;
    st.scanned = false;
    st.findings_emitted = false;
    if (trancheCount === 0) st.phase = "done";
  } else if (unit.kind === "active") {
    st.phase = "tranche";
    st.active_index = (st.active_index || 0) + 1;
  } else if (unit.kind === "scan") {
    st.scanned = true;
  } else if (unit.kind === "emit") {
    st.findings_emitted = true;
  } else if (unit.kind === "advance") {
    st.tranche_index = (st.tranche_index || 0) + 1;
    st.active_index = 0;
    st.scanned = false;
    st.findings_emitted = false;
    st.phase = st.tranche_index >= trancheCount ? "done" : "tranche";
  } else if (unit.kind === "done") {
    st.phase = "done";
  }
  st.complete = st.phase === "done";
  return st;
}

function readStdin() {
  return readFileSync(0, "utf8");
}

function main() {
  const cmd = process.argv[2] || "config";
  const config = loadBatchConfig();
  if (cmd === "config") {
    process.stdout.write(`${JSON.stringify(config, null, 2)}\n`);
    return;
  }
  if (cmd === "order-hosts") {
    const hosts = readStdin().split("\n").map((h) => h.trim()).filter(Boolean);
    const ranked = rankHosts(hosts.map((host) => ({ host })), config);
    process.stdout.write(ranked.map((row) => row.host).join("\n"));
    if (ranked.length) process.stdout.write("\n");
    return;
  }
  process.stderr.write("usage: tranche.mjs config|order-hosts\n");
  process.exitCode = 2;
}

const invoked = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invoked) main();
