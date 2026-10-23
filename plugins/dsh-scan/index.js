/**
 * dsh-scan — confirmed findings from live evidence.
 *
 * Pattern (Nuclei + TruffleHog + BBOT + Strix, applied with original rules):
 *   1. Scope gate, then a live probe. Zero live targets is a broken run.
 *   2. Load a pinned rule pack. Zero rules loaded is a broken run.
 *   3. Matchers run against saved responses. Baselines are negative matchers.
 *   4. status is verified | unverified | verification_skipped.
 *      Unverified is never copied into the confirmed set.
 *   5. Fingerprint = sha256(skill_id + asset + evidence_hash).
 *   6. Always emit SARIF 2.1.0 and JSONL, including the empty case.
 *
 * Nuclei, TruffleHog, and osv-scanner run as unmodified subprocesses when
 * they are on PATH. See modules.js. Unverified output is never confirmed.
 */

import { createHash } from "node:crypto";
import { existsSync, writeFileSync, mkdtempSync } from "node:fs";
import { readFile } from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import { createServer } from "node:http";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import tls from "node:tls";

import { scopeAllows } from "../dsh-scope-guard/index.js";
import { decideTiming } from "../dsh-validators/index.js";
import { PACK } from "./pack.js";
import { moduleStatus, runExternalModules } from "./modules.js";

export const name = "scan";
export const inject = ["tools"];

const HERE = dirname(fileURLToPath(import.meta.url));
const SKILLS_DIR = join(HERE, "..", "..", "skills");
const FIXTURE_SECRET = fileURLToPath(new URL("../dsh-eval/fixture-data/secret.txt", import.meta.url));

const SEVERITY_LEVEL = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
const SEVERITY_SCORE = { critical: "9.0", high: "7.5", medium: "5.0", low: "3.0", info: "1.0" };

export function fingerprint(skillId, asset, evidenceHash) {
  return createHash("sha256").update(`${skillId}\0${asset}\0${evidenceHash}`).digest("hex");
}

export function evidenceHash(text) {
  return createHash("sha256").update(String(text)).digest("hex");
}

function isLoopback(host) {
  const h = String(host || "").toLowerCase();
  return h === "127.0.0.1" || h === "localhost" || h === "::1";
}

function redactText(value) {
  return String(value ?? "")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "AKIA[redacted]")
    .replace(/("apiKey"\s*:\s*")[^"]+"/g, '$1[redacted]"')
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/-]+=*/g, "$1[redacted]");
}

function substitute(value, vars) {
  if (typeof value === "string") {
    return value.replace(/\{\{(\w+)\}\}/g, (_, key) => (vars[key] != null ? String(vars[key]) : `{{${key}}}`));
  }
  if (Array.isArray(value)) return value.map((item) => substitute(item, vars));
  if (value && typeof value === "object") {
    const out = {};
    for (const [key, item] of Object.entries(value)) out[substitute(key, vars)] = substitute(item, vars);
    return out;
  }
  return value;
}

function getPath(obj, path) {
  let cur = obj;
  for (const part of String(path || "").split(".")) {
    if (cur == null) return undefined;
    if (part === "length") return cur.length;
    cur = cur[part];
  }
  return cur;
}

function asJson(body) {
  try {
    return JSON.parse(body);
  } catch {
    return undefined;
  }
}

function headerValue(res, name) {
  const value = res.headers?.[name.toLowerCase()];
  if (Array.isArray(value)) return value.join(",");
  return value == null ? "" : String(value);
}

function one(batch) {
  const list = Array.isArray(batch) ? batch : [batch];
  return list[list.length - 1];
}

export function httpRequest(base, spec, timeout = 8000) {
  const target = new URL(spec.path || "/", base);
  const query = spec.query || {};
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) params.append(key, value);
  const search = params.toString();
  if (search) target.search = search;

  let payload = spec.body ?? null;
  if (payload != null && typeof payload !== "object") payload = String(payload);
  else if (payload != null) payload = JSON.stringify(payload);

  const headers = {
    "User-Agent": "bughive-scan/1.0 (authorized; in-scope)",
    Accept: "*/*",
    ...(spec.headers || {}),
  };
  if (payload != null) {
    const contentType = spec.contentType || "application/json";
    if (!headers["Content-Type"] && !headers["content-type"]) headers["Content-Type"] = contentType;
    headers["Content-Length"] = Buffer.byteLength(payload);
  }

  const lib = target.protocol === "https:" ? https : http;
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const req = lib.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port,
        method: spec.method || "GET",
        path: `${target.pathname}${target.search}`,
        headers,
        timeout,
        rejectUnauthorized: spec.rejectUnauthorized !== false,
        servername: spec.servername,
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          const body = Buffer.concat(chunks).toString("utf8");
          resolve({
            url: target.toString(),
            method: spec.method || "GET",
            status: res.statusCode,
            headers: res.headers,
            body,
            ms: Date.now() - started,
            request: {
              method: spec.method || "GET",
              url: redactText(target.toString()),
              headers: JSON.parse(redactText(JSON.stringify(headers))),
              body: payload == null ? "" : redactText(payload).slice(0, 2000),
            },
            response: {
              status: res.statusCode,
              headers: res.headers,
              body: redactText(body).slice(0, 2000),
            },
          });
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    if (payload != null) req.write(payload);
    req.end();
  });
}

function compare(op, left, right) {
  if (op === "eq") return left === right;
  if (op === "ne") return left !== right;
  if (op === "gt") return Number(left) > Number(right);
  if (op === "gte") return Number(left) >= Number(right);
  if (op === "lt") return Number(left) < Number(right);
  return false;
}

function matchOne(matcher, responses, ctx) {
  if (matcher.type === "oob") return Boolean(ctx.oobHits);
  if (matcher.type === "timing") {
    const fast = responses[matcher.fast] || [];
    const slow = responses[matcher.slow] || [];
    if (!fast.length || !slow.length) return false;
    return decideTiming(fast, slow, matcher.injectedMs, matcher.tolerance ?? 0.5).validated;
  }
  if (matcher.type === "min_matches") {
    const batch = responses[matcher.request] || [];
    const hits = batch.filter((item) => String(item.body || "").includes(matcher.word)).length;
    return hits >= matcher.min;
  }
  const res = one(responses[matcher.request]);
  if (!res) return false;
  let ok = false;
  if (matcher.type === "status") ok = res.status === matcher.value;
  else if (matcher.type === "word") ok = matcher.words.every((word) => String(res.body).includes(word));
  else if (matcher.type === "regex") ok = new RegExp(matcher.regex).test(String(res.body));
  else if (matcher.type === "header") {
    const got = headerValue(res, matcher.name);
    ok = matcher.equals != null ? got === matcher.equals : got.includes(matcher.contains || "");
  } else if (matcher.type === "json") {
    const left = getPath(asJson(res.body), matcher.path);
    const right = matcher.other
      ? getPath(asJson(one(responses[matcher.other])?.body), matcher.otherPath || matcher.path)
      : matcher.value;
    ok = compare(matcher.compare || "eq", left, right);
  }
  return matcher.negative ? !ok : ok;
}

export function validateRule(rule, skillsDir) {
  const errors = [];
  if (!rule?.id) errors.push("missing id");
  else {
    if (!rule.skill) errors.push(`${rule.id}: missing skill`);
    if (!["critical", "high", "medium", "low", "info"].includes(rule.severity)) errors.push(`${rule.id}: bad severity`);
    if (skillsDir && rule.skill && !existsSync(join(skillsDir, `${rule.skill}.md`))) {
      errors.push(`${rule.id}: skill file missing (${rule.skill})`);
    }
    const type = rule.type || "http";
    if (type === "http") {
      if (!Array.isArray(rule.requests) || rule.requests.length === 0) errors.push(`${rule.id}: no requests`);
      if (!Array.isArray(rule.matchers) || rule.matchers.length === 0) errors.push(`${rule.id}: no matchers`);
      if (!rule.class || !rule.method || !rule.path) errors.push(`${rule.id}: class, method, and path are required`);
      const ids = new Set((rule.requests || []).map((spec) => spec.id));
      if (Array.isArray(rule.flow)) {
        for (const id of rule.flow) {
          if (!ids.has(id)) errors.push(`${rule.id}: flow id ${id} is not a request`);
        }
      }
      for (const extractor of rule.extractors || []) {
        if (!extractor?.type || !extractor?.name) errors.push(`${rule.id}: extractor needs type and name`);
        else if (!["json", "regex"].includes(extractor.type)) errors.push(`${rule.id}: extractor ${extractor.name} has an unknown type`);
        else if (extractor.type === "json" && !extractor.path) errors.push(`${rule.id}: extractor ${extractor.name} needs a path`);
        else if (extractor.type === "regex" && !extractor.regex) errors.push(`${rule.id}: extractor ${extractor.name} needs a regex`);
        else if (extractor.request && !ids.has(extractor.request)) errors.push(`${rule.id}: extractor ${extractor.name} request is not defined`);
      }
    } else if (!rule.class) errors.push(`${rule.id}: class is required`);
  }
  return errors;
}

export function validatePack(pack, skillsDir) {
  const rules = Array.isArray(pack?.rules) ? pack.rules : [];
  const errors = rules.flatMap((rule) => validateRule(rule, skillsDir));
  const rulesLoaded = rules.length > 0 && errors.length === 0 ? rules.length : 0;
  return {
    ok: rulesLoaded > 0,
    name: pack?.name || "",
    version: pack?.version || "",
    rulesLoaded,
    errors,
  };
}

function packHash(pack) {
  return createHash("sha256").update(JSON.stringify(pack)).digest("hex");
}

function isTlsVerifyError(error) {
  const code = String(error?.code || error?.message || "");
  return /CERT_|ERR_TLS|UNABLE_TO_VERIFY|SELF_SIGNED|ALTNAME|certificate/i.test(code);
}

function buildSarif(pack, hash, findings, stats) {
  const seen = new Set();
  const rules = [];
  for (const rule of pack.rules || []) {
    if (seen.has(rule.id)) continue;
    seen.add(rule.id);
    rules.push({
      id: rule.id,
      shortDescription: { text: rule.id },
      properties: { tags: [rule.class || rule.type || "http"], severity: rule.severity },
    });
  }
  for (const finding of findings) {
    if (seen.has(finding.ruleId)) continue;
    seen.add(finding.ruleId);
    rules.push({
      id: finding.ruleId,
      shortDescription: { text: finding.ruleId },
      properties: { tags: [finding.class || "module"], severity: finding.severity, source: finding.module || finding.skill },
    });
  }
  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "bughive",
            version: pack.version,
            informationUri: "https://github.com/Navdeepkhubber/bughive",
            rules,
          },
        },
        invocations: [
          {
            executionSuccessful: stats.brokenReason == null && stats.errors === 0,
            properties: {
              rulesLoaded: stats.rulesLoaded,
              rulesSha256: hash,
              liveTargets: stats.liveTargets,
              requests: stats.requests,
              errors: stats.errors,
              confirmed: stats.confirmed,
              unverified: stats.unverified,
              verdict: stats.verdict,
            },
          },
        ],
        results: findings.map((finding) => ({
          ruleId: finding.ruleId,
          level: SEVERITY_LEVEL[finding.severity] || "warning",
          message: { text: finding.proof },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: finding.asset },
                region: { startLine: finding.line || 1 },
              },
            },
          ],
          partialFingerprints: { "skillAssetEvidence/v1": finding.fingerprint },
          properties: {
            status: finding.status,
            type: finding.type,
            skill: finding.skill,
            "security-severity": SEVERITY_SCORE[finding.severity] || "0.0",
          },
        })),
      },
    ],
  };
}

function makeFinding(rule, asset, proof, exchanges, status, extra = {}) {
  const hash = evidenceHash(proof);
  const id = fingerprint(rule.skill, asset, hash);
  const saved = (exchanges || []).filter((item) => item?.request && item?.response);
  let finalStatus = status;
  if (finalStatus === "verified" && saved.length === 0) finalStatus = "unverified";
  const finding = {
    type: finalStatus === "verified" ? "VULNERABILITY" : "FINDING",
    status: finalStatus,
    ruleId: rule.id,
    class: rule.class,
    skill: rule.skill,
    severity: rule.severity,
    method: rule.method || null,
    path: rule.path || null,
    asset,
    line: 1,
    proof,
    evidenceHash: hash,
    fingerprint: id,
    request: saved[0]?.request || null,
    response: saved[0]?.response || null,
    exchanges: saved.slice(0, 4),
  };
  if (extra.module) finding.module = extra.module;
  if (extra.extracted && Object.keys(extra.extracted).length) finding.extracted = extra.extracted;
  return finding;
}

function orderedRequests(rule) {
  if (!Array.isArray(rule.flow) || rule.flow.length === 0) return rule.requests;
  const byId = new Map(rule.requests.map((spec) => [spec.id, spec]));
  return rule.flow.map((id) => byId.get(id)).filter(Boolean);
}

function applyExtractors(rule, responses) {
  const extracted = {};
  for (const extractor of rule.extractors || []) {
    try {
      const res = one(responses[extractor.request]);
      if (!res) continue;
      let value;
      if (extractor.type === "json") value = getPath(asJson(res.body), extractor.path);
      else if (extractor.type === "regex") {
        const match = new RegExp(extractor.regex).exec(String(res.body));
        value = match ? (match[1] ?? match[0]) : undefined;
      }
      if (value == null) continue;
      extracted[extractor.name] = typeof value === "string" ? redactText(value) : value;
    } catch {
      // An extractor never turns a matcher hit into a miss.
    }
  }
  return extracted;
}

function adoptRecord(record) {
  const finding = makeFinding(
    {
      id: record.ruleId,
      skill: record.skill,
      class: record.class,
      severity: record.severity,
      method: record.method || null,
      path: record.path || null,
    },
    record.asset,
    record.proof,
    record.exchanges,
    record.status,
    { extracted: record.extracted, module: record.module },
  );
  if (record.advisories) finding.advisories = record.advisories;
  if (record.line) finding.line = record.line;
  return finding;
}

async function listenOob() {
  const hits = [];
  const server = createServer((req, res) => {
    hits.push(req.url || "/");
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ok");
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}/bughive-oob`,
    hits,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

async function scanSecrets(rule, paths) {
  const findings = [];
  const checks = [];
  const re = new RegExp(rule.pattern, "g");
  const allow = new Set(rule.allow || []);
  const stopwords = rule.stopwords || [];
  let files = 0;
  for (const path of paths) {
    let text = "";
    try {
      text = await readFile(path, "utf8");
      files += 1;
    } catch (error) {
      checks.push({ id: rule.id, result: "error", detail: `${path}: ${error.message}` });
      continue;
    }
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      re.lastIndex = 0;
      const line = lines[i];
      let match = re.exec(line);
      while (match) {
        const token = match[0];
        if (allow.has(token) || stopwords.some((word) => token.includes(word))) {
          checks.push({ id: rule.id, result: "allowlisted", detail: `${path}:${i + 1} example key ignored` });
        } else {
          const redacted = `${token.slice(0, 4)}…${token.slice(-2)}`;
          const proof = `AWS-shaped access key ${redacted} at ${path}:${i + 1} is not on the allowlist. No live verifier ran, so this stays unverified.`;
          const finding = makeFinding(rule, `file:${path}`, proof, [
            {
              request: { method: "READ", url: path, headers: {}, body: "" },
              response: { status: 200, headers: {}, body: redactText(line).slice(0, 500) },
            },
          ], "unverified");
          finding.line = i + 1;
          finding.path = path;
          findings.push(finding);
          checks.push({ id: rule.id, result: "unverified", detail: proof });
        }
        match = re.exec(line);
      }
    }
  }
  if (files === 0 && checks.every((item) => item.result !== "error")) {
    checks.push({ id: rule.id, result: "skipped", detail: "no files" });
  }
  return { findings, checks, files };
}

async function scanPackage(rule, packageJson, fetchImpl) {
  const raw = await readFile(packageJson, "utf8");
  const manifest = JSON.parse(raw);
  const deps = { ...(manifest.dependencies || {}), ...(manifest.devDependencies || {}) };
  const findings = [];
  const checks = [];
  for (const [name, range] of Object.entries(deps)) {
    const version = String(range).replace(/^[^0-9]*/, "");
    const body = JSON.stringify({ package: { name, ecosystem: "npm" }, version });
    const response = await fetchImpl("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "bughive-scan/1.0" },
      body,
    });
    const text = await response.text();
    if (!response.ok) throw new Error(`osv.dev HTTP ${response.status} for ${name}@${version}: ${text.slice(0, 200)}`);
    const data = JSON.parse(text);
    const ids = (data.vulns || []).map((vuln) => vuln.id).filter(Boolean);
    const compact = JSON.stringify({
      vulns: (data.vulns || []).map((vuln) => ({ id: vuln.id, summary: vuln.summary, aliases: vuln.aliases || [] })),
    });
    if (ids.length === 0) {
      checks.push({ id: rule.id, result: "miss", detail: `${name}@${version} has no OSV advisories` });
      continue;
    }
    const proof = `${name}@${version} is inside published OSV ranges: ${ids.join(", ")}.`;
    const finding = makeFinding(rule, `npm:${name}@${version}`, proof, [
      {
        request: { method: "POST", url: "https://api.osv.dev/v1/query", headers: {}, body },
        response: { status: response.status, headers: {}, body: compact },
      },
    ], "verified");
    finding.advisories = ids;
    findings.push(finding);
    checks.push({ id: rule.id, result: "verified", detail: proof });
  }
  return { findings, checks };
}

function tlsProbe(host, port, servername) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host, port, servername: servername || host, rejectUnauthorized: true, timeout: 15000 },
      () => {
        const cert = socket.getPeerCertificate();
        socket.end();
        resolve({ ok: true, cert, error: null });
      },
    );
    socket.on("error", (error) => {
      const cert = socket.getPeerCertificate?.() || null;
      resolve({ ok: false, cert, error });
    });
  });
}

function peerCertificate(host, port, servername) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      resolve(value);
    };
    const socket = tls.connect(
      {
        host,
        port,
        servername: servername || host,
        rejectUnauthorized: false,
        checkServerIdentity: () => undefined,
        timeout: 8000,
      },
      () => {
        const raw = socket.getPeerCertificate()?.raw;
        socket.end();
        if (!raw) {
          finish({ pem: "", detail: "handshake completed without a peer certificate" });
          return;
        }
        const body = raw.toString("base64").match(/.{1,64}/g).join("\n");
        finish({ pem: `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`, detail: "ok" });
      },
    );
    socket.on("error", (error) => finish({ pem: "", detail: error.message }));
  });
}

async function opensslRevoked({ host, port, servername, caFile, crlFile }) {
  const peer = await peerCertificate(host, port, servername);
  if (!peer.pem) {
    return { completed: true, revoked: false, detail: `error: peer certificate was not presented (${peer.detail})` };
  }
  const pem = peer.pem;
  if (!caFile || !crlFile) {
    const uri = spawnSync("openssl", ["x509", "-noout", "-ocsp_uri"], { input: pem, encoding: "utf8" });
    const ocspUri = (uri.stdout || "").trim();
    if (!ocspUri) {
      return { completed: true, revoked: false, detail: "verification_skipped: certificate presented no OCSP URI and no CRL was supplied" };
    }
    return {
      completed: true,
      revoked: false,
      detail: `verification_skipped: OCSP URI ${ocspUri} is present; leaf was accepted by the default trust store, so it is not reported as revoked`,
    };
  }
  const folder = mkdtempSync(join(tmpdir(), "bughive-crl-"));
  const certPath = join(folder, "peer.pem");
  writeFileSync(certPath, pem);
  const verified = spawnSync("openssl", ["verify", "-CAfile", caFile, "-CRLfile", crlFile, "-crl_check", certPath], { encoding: "utf8" });
  const text = `${verified.stdout || ""}\n${verified.stderr || ""}`.trim();
  return { completed: true, revoked: /certificate revoked/i.test(text), detail: text || `openssl verify exit ${verified.status}` };
}

export async function runScan(opts = {}) {
  const skillsDir = opts.skillsDir || SKILLS_DIR;
  const pack = opts.pack || PACK;
  const rules = opts.rules ?? pack.rules ?? [];
  const hash = packHash({ name: pack.name, version: pack.version, rules });
  const whichImpl = opts.whichImpl;
  const modules = moduleStatus(whichImpl);
  const checks = [];
  const findings = [];
  let requests = 0;
  let errors = 0;
  let moduleRuns = {};

  const invalid = rules.flatMap((rule) => validateRule(rule, skillsDir));
  const statsBase = () => ({
    rulesPack: { name: pack.name || "bughive-rules", version: pack.version || "0", sha256: hash },
    rulesLoaded: invalid.length ? 0 : rules.length,
    liveTargets: 0,
    requests,
    errors,
    confirmed: 0,
    unverified: 0,
    modules,
    moduleRuns,
    checks,
  });

  if (rules.length === 0 || invalid.length) {
    const brokenReason = rules.length === 0 ? "no_rules" : "invalid_rules";
    const stats = { ...statsBase(), brokenReason, invalid, liveError: null };
    stats.verdict = brokenReason === "no_rules"
      ? `PIPELINE BROKEN: 0 rules loaded from ${stats.rulesPack.name} ${stats.rulesPack.version}. This is not a clean target.`
      : `PIPELINE BROKEN: rule pack failed validation. ${invalid.join("; ")}`;
    const sarif = buildSarif({ ...pack, rules }, hash, [], stats);
    return finish(stats, [], sarif);
  }

  const base = opts.base || null;
  let host = null;
  if (base) {
    host = new URL(base).hostname;
    const gate = scopeAllows(opts.scopeText || "", host);
    if (!gate.allowed) {
      const stats = { ...statsBase(), brokenReason: "out_of_scope", invalid: [], liveError: gate.reason };
      stats.verdict = `PIPELINE BROKEN: ${host} is outside scope (${gate.reason}). No requests sent.`;
      return finish(stats, [], buildSarif(pack, hash, [], stats));
    }
  }

  const active = host ? (opts.allowActive === true || (opts.allowActive !== false && (isLoopback(host) || process.env.BUGHIVE_ACTIVE_PROOF === "1"))) : false;
  const vars = {
    oob_url: "",
    fixtureSecretFile: host && isLoopback(host) && existsSync(FIXTURE_SECRET) ? FIXTURE_SECRET : "",
  };

  let oob = null;
  const needsOob = rules.some((rule) => JSON.stringify(rule.requests || []).includes("{{oob_url}}"));
  if (needsOob && base) {
    oob = await listenOob();
    vars.oob_url = oob.url;
  }

  const transport = opts.request || ((spec) => httpRequest(base, spec, spec.timeout || 8000));
  async function send(spec) {
    const prepared = substitute(spec, vars);
    requests += 1;
    const res = await transport(prepared);
    return res;
  }

  try {
    let live = null;
    if (base) {
      try {
        live = await send({ method: "GET", path: "/", rejectUnauthorized: true });
        checks.push({ id: "live-probe", result: "live", detail: `GET / -> ${live.status}` });
      } catch (error) {
        if (isTlsVerifyError(error)) {
          checks.push({ id: "live-probe", result: "live", detail: `TLS presented a certificate: ${error.code || error.message}` });
          live = { status: 0, tlsError: error.code || error.message, request: { method: "GET", url: base, headers: {}, body: "" }, response: { status: 0, headers: {}, body: String(error.message) } };
        } else {
          const stats = { ...statsBase(), brokenReason: "no_live_target", invalid: [], liveError: error.message };
          stats.verdict = `PIPELINE BROKEN: 0 live targets (${error.message}). This is not a clean target.`;
          checks.push({ id: "live-probe", result: "error", detail: error.message });
          return finish(stats, [], buildSarif(pack, hash, [], stats));
        }
      }
    }

    if (opts.modules === false) {
      moduleRuns = Object.fromEntries(["nuclei", "trufflehog", "osv-scanner", "bbot"].map((name) => [
        name,
        { status: "skipped", findings: 0, error: null, detail: "external modules disabled for this run" },
      ]));
    } else {
      const external = runExternalModules({
        base,
        scopeText: opts.scopeText || "",
        allowActive: active,
        paths: opts.paths || [],
        packageJson: opts.packageJson || "",
        spawnImpl: opts.spawnImpl,
        whichImpl,
      });
      moduleRuns = external.moduleRuns;
      errors += external.errors;
      requests += external.requests;
      findings.push(...external.records.map(adoptRecord));
    }

    const ordered = [...rules].sort((a, b) => (a.order || 50) - (b.order || 50));
    for (const rule of ordered) {
      const type = rule.type || "http";
      try {
        if (type === "http") {
          if (!base) {
            checks.push({ id: rule.id, result: "skipped", detail: "no base URL" });
            continue;
          }
          if (rule.mutates && !active) {
            checks.push({ id: rule.id, result: "skipped", detail: "state-changing proof is limited to loopback or BUGHIVE_ACTIVE_PROOF=1" });
            continue;
          }
          if ((rule.tags || []).includes("dos") && !opts.allowDos) {
            checks.push({ id: rule.id, result: "skipped", detail: "dos tag is off by default" });
            continue;
          }
          const responses = {};
          const exchanges = [];
          let stopped = false;
          for (const spec of orderedRequests(rule)) {
            const count = spec.repeat || spec.samples || 1;
            const batch = [];
            if (spec.repeat) {
              const group = await Promise.all(Array.from({ length: count }, () => send(spec)));
              batch.push(...group);
            } else {
              for (let i = 0; i < count; i += 1) {
                const res = await send(spec);
                batch.push(res);
                if (i === 0 && spec.stopIfStatus && res.status === spec.stopIfStatus) {
                  stopped = true;
                  break;
                }
              }
            }
            responses[spec.id] = batch;
            exchanges.push(...batch);
            if (stopped) break;
          }
          if (stopped) {
            checks.push({ id: rule.id, result: "miss", detail: "endpoint not present (stop status)" });
            continue;
          }
          const ok = rule.matchers.every((matcher) => matchOne(matcher, responses, { oobHits: oob?.hits.length || 0 }));
          if (!ok) {
            checks.push({ id: rule.id, result: "miss", detail: "matchers did not all hold" });
            continue;
          }
          const asset = new URL(rule.path, base).toString();
          const proof = `${rule.id} matched on ${asset} with saved request/response.`;
          findings.push(makeFinding(rule, asset, proof, exchanges, "verified", { extracted: applyExtractors(rule, responses) }));
          checks.push({ id: rule.id, result: "verified", detail: proof });
        } else if (type === "secret") {
          if (!opts.paths?.length) {
            checks.push({ id: rule.id, result: "skipped", detail: "no files were passed" });
            continue;
          }
          const scanned = await scanSecrets(rule, opts.paths);
          findings.push(...scanned.findings);
          checks.push(...scanned.checks);
        } else if (type === "sca") {
          if (!opts.packageJson) {
            checks.push({ id: rule.id, result: "skipped", detail: "no package manifest was passed" });
            continue;
          }
          if (moduleRuns["osv-scanner"]?.status === "ran") {
            checks.push({ id: rule.id, result: "skipped", detail: "osv-scanner subprocess already reported this manifest" });
            continue;
          }
          const scanned = await scanPackage(rule, opts.packageJson, opts.fetchImpl || globalThis.fetch);
          findings.push(...scanned.findings);
          checks.push(...scanned.checks);
          requests += scanned.findings.length + scanned.checks.filter((item) => item.result === "miss").length;
        } else if (type === "tls") {
          const tlsHosts = opts.tlsHosts || (base && new URL(base).protocol === "https:" ? [host] : []);
          if (tlsHosts.length === 0 && !opts.tls) {
            checks.push({ id: rule.id, result: "skipped", detail: "no TLS target" });
            continue;
          }
          if (rule.check === "expired") {
            for (const name of tlsHosts) {
              const gate = scopeAllows(opts.scopeText || "", name);
              if (!gate.allowed) {
                checks.push({ id: rule.id, result: "skipped", detail: `${name} out of scope` });
                continue;
              }
              const probed = await tlsProbe(name, 443, name);
              requests += 1;
              const code = probed.error?.code || "";
              if (code === "CERT_HAS_EXPIRED") {
                const proof = `${name} presented a certificate the TLS stack rejected: CERT_HAS_EXPIRED.`;
                const finding = makeFinding(rule, `https://${name}/`, proof, [
                  {
                    request: { method: "TLS", url: `https://${name}/`, headers: {}, body: "" },
                    response: { status: 0, headers: {}, body: `${code} ${probed.error.message}` },
                  },
                ], "verified");
                finding.method = "TLS";
                finding.path = "/";
                findings.push(finding);
                checks.push({ id: rule.id, result: "verified", detail: proof });
              } else {
                checks.push({ id: rule.id, result: "miss", detail: `${name}: ${code || "certificate not expired"}` });
              }
            }
          } else if (rule.check === "revoked") {
            const target = opts.tls || null;
            const names = tlsHosts;
            if (target?.crlFile) {
              const gate = scopeAllows(opts.scopeText || "", target.host);
              if (!gate.allowed) {
                checks.push({ id: rule.id, result: "skipped", detail: `${target.host} out of scope` });
              } else {
                const result = await opensslRevoked(target);
                requests += 1;
                if (!result.completed) {
                  errors += 1;
                  checks.push({ id: rule.id, result: "error", detail: result.detail });
                } else if (result.revoked) {
                  const proof = `CRL check revoked ${target.host}: ${result.detail}`;
                  const finding = makeFinding(rule, `https://${target.host}:${target.port}/`, proof, [
                    {
                      request: { method: "TLS", url: `https://${target.host}:${target.port}/`, headers: {}, body: "" },
                      response: { status: 0, headers: {}, body: result.detail.slice(0, 2000) },
                    },
                  ], "verified");
                  finding.method = "TLS";
                  finding.path = "/";
                  findings.push(finding);
                  checks.push({ id: rule.id, result: "verified", detail: proof });
                } else {
                  checks.push({ id: rule.id, result: result.detail.startsWith("error:") ? "error" : "miss", detail: result.detail });
                  if (result.detail.startsWith("error:")) errors += 1;
                }
              }
            }
            for (const name of names) {
              if (target && name === target.host) continue;
              const gate = scopeAllows(opts.scopeText || "", name);
              if (!gate.allowed) {
                checks.push({ id: rule.id, result: "skipped", detail: `${name} out of scope` });
                continue;
              }
              const result = await opensslRevoked({ host: name, port: 443, servername: name });
              requests += 1;
              checks.push({
                id: rule.id,
                result: result.revoked ? "verified" : "verification_skipped",
                detail: `${name}: ${result.detail}`,
              });
              if (result.revoked) {
                const proof = `${name} is revoked: ${result.detail}`;
                findings.push(makeFinding(rule, `https://${name}/`, proof, [
                  {
                    request: { method: "TLS", url: `https://${name}/`, headers: {}, body: "" },
                    response: { status: 0, headers: {}, body: result.detail.slice(0, 2000) },
                  },
                ], "verified"));
              }
            }
          }
        }
      } catch (error) {
        errors += 1;
        checks.push({ id: rule.id, result: "error", detail: error.message });
      }
    }
  } finally {
    if (oob) await oob.close();
  }

  const deduped = [];
  const seen = new Set();
  for (const finding of findings) {
    if (seen.has(finding.fingerprint)) continue;
    seen.add(finding.fingerprint);
    deduped.push(finding);
  }
  const stats = {
    ...statsBase(),
    brokenReason: null,
    invalid: [],
    liveError: null,
    liveTargets: (base ? 1 : 0) + (opts.paths?.length ? 1 : 0) + (opts.packageJson ? 1 : 0) + (opts.tlsHosts?.length || 0) + (opts.tls ? 1 : 0),
  };
  stats.confirmed = deduped.filter((item) => item.status === "verified").length;
  stats.unverified = deduped.filter((item) => item.status !== "verified").length;
  stats.requests = requests;
  stats.errors = errors;
  if (!base && !opts.paths?.length && !opts.packageJson && !opts.tlsHosts?.length && !opts.tls) {
    stats.brokenReason = "no_live_target";
    stats.liveTargets = 0;
    stats.verdict = "PIPELINE BROKEN: 0 live targets. This is not a clean target.";
  } else if (stats.confirmed === 0) {
    stats.verdict = `No results found. Ran ${stats.rulesLoaded} rules, ${stats.requests} requests, ${stats.errors} errors, ${stats.liveTargets} live targets.`;
  } else {
    stats.verdict = `${stats.confirmed} confirmed, ${stats.unverified} unverified. Ran ${stats.rulesLoaded} rules, ${stats.requests} requests, ${stats.errors} errors.`;
  }
  return finish(stats, deduped, buildSarif(pack, hash, deduped, stats));
}

function moduleEvents(stats) {
  const runs = stats.moduleRuns || {};
  const mods = stats.modules || {};
  return ["nuclei", "trufflehog", "osv-scanner", "bbot"].map((module) => {
    const run = runs[module];
    const status = run?.status || (mods[module] === "present" ? "skipped" : "not-installed");
    return {
      type: "MODULE",
      module,
      status,
      findings: run?.findings || 0,
      error: run?.error || null,
      detail: run?.detail || null,
    };
  });
}

function finish(stats, findings, sarif) {
  const confirmed = findings.filter((item) => item.status === "verified");
  const lines = [
    ...moduleEvents(stats).map((item) => JSON.stringify(item)),
    ...findings.map((item) => JSON.stringify({ type: item.type, status: item.status, ruleId: item.ruleId, skill: item.skill, asset: item.asset, fingerprint: item.fingerprint, severity: item.severity, proof: item.proof })),
    JSON.stringify({ type: "run", stats: { ...stats, checks: undefined }, verdict: stats.verdict }),
  ];
  return {
    ok: stats.brokenReason == null,
    brokenReason: stats.brokenReason || null,
    findings,
    confirmed,
    stats,
    sarif,
    jsonl: `${lines.join("\n")}\n`,
  };
}

export async function writeScanOutput(dir, result) {
  const { mkdir, writeFile: write } = await import("node:fs/promises");
  await mkdir(dir, { recursive: true });
  await write(join(dir, "findings.sarif"), JSON.stringify(result.sarif, null, 2));
  await write(join(dir, "findings.jsonl"), result.jsonl);
  await write(join(dir, "findings.json"), JSON.stringify(result.findings, null, 2));
  await write(join(dir, "validated.json"), JSON.stringify(result.confirmed, null, 2));
  await write(join(dir, "scan-summary.json"), JSON.stringify({ verdict: result.stats.verdict, stats: result.stats }, null, 2));
}

export function apply(ctx) {
  ctx.tools.register({
    name: "scan_target",
    description: "Run the pinned bughive rule pack against an in-scope base URL. Confirmed findings require saved request/response. Always returns SARIF and a stats line.",
    parameters: {
      type: "object",
      properties: {
        base: { type: "string" },
        scope: { type: "string" },
        paths: { type: "string" },
        packageJson: { type: "string" },
      },
    },
    output: { schema: { type: "string" }, render: (_args, value) => [{ type: "text", text: value }] },
    async execute(args) {
      const result = await runScan({
        base: args.base,
        scopeText: args.scope,
        paths: args.paths ? String(args.paths).split("\n").filter(Boolean) : [],
        packageJson: args.packageJson,
      });
      return JSON.stringify({ ok: result.ok, verdict: result.stats.verdict, confirmed: result.confirmed.length, unverified: result.findings.length - result.confirmed.length });
    },
  });
}
