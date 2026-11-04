/**
 * Execute an authored Steps block against an in-scope base URL.
 *
 * The HTTP client is the validators' fetchSample. Assertions go through the
 * scan matcher (`matchSavedResponse`) so status, word, regex, and header
 * checks stay the ones the pipeline already uses. Nothing is fetched unless
 * the skill wrote both a request and a machine-checkable success condition.
 */
import { fetchSample } from "../dsh-validators/index.js";
import { scopeAllows } from "../dsh-scope-guard/index.js";
import { matchSavedResponse } from "../dsh-scan/index.js";
import { parseSteps } from "./parse.js";

const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
const PLACEHOLDER = /\{\{\s*([^}]+?)\s*\}\}/g;

function asParsed(input) {
  if (typeof input === "string" || input == null) return parseSteps(input || "");
  if (Array.isArray(input.blocks)) return input;
  return parseSteps("");
}

function emptyEvidence(extra = {}) {
  return {
    executed: false,
    observations: [],
    success: [],
    falsePositiveGuard: [],
    ...extra,
  };
}

function finish(result, reason, evidence, runnable) {
  return { result, runnable, reason, evidence };
}

function canRun(block) {
  if (!block || block.runnable !== true) return false;
  if (!Array.isArray(block.requests) || block.requests.length === 0) return false;
  if (!Array.isArray(block.success?.checks) || block.success.checks.length === 0) return false;
  if (block.success.unusable) return false;
  if (block.falsePositiveGuard?.present && (block.falsePositiveGuard.unusable || block.falsePositiveGuard.checks.length === 0)) {
    return false;
  }
  return block.requests.every((req) => METHODS.has(req.method) && typeof req.path === "string" && req.path && !req.incomplete);
}

function resolveRequestUrl(request, baseUrl) {
  const base = String(baseUrl || "").replace(/\/+$/, "");
  let path = String(request.path || "");
  let problem = null;
  path = path.replace(PLACEHOLDER, (whole, name) => {
    const key = String(name).trim().toLowerCase();
    if (key === "baseurl" || key === "base" || key === "target") {
      if (!base) problem = "in-scope base URL missing";
      return base;
    }
    problem = `unresolved placeholder {{${String(name).trim()}}}`;
    return whole;
  });
  if (problem) return { error: problem };
  if (/^https?:\/\//i.test(path)) return { url: path };
  if (path.startsWith("/")) {
    if (!base) return { error: "in-scope base URL missing" };
    return { url: `${base}${path}` };
  }
  return { error: "no authored HTTP request" };
}

async function doFetch(url, request, opts) {
  const headers = {};
  for (const [key, value] of Object.entries(request.headers || {})) {
    if (typeof value !== "string") return { error: "authored header is not a string" };
    headers[key] = value;
  }
  if (request.body !== undefined && typeof request.body !== "string") {
    return { error: "authored body is not a string" };
  }
  if (opts.fetchImpl) return opts.fetchImpl(url, request);
  const init = { method: request.method, headers };
  if (request.body !== undefined && request.method !== "GET" && request.method !== "HEAD") init.body = request.body;
  return fetchSample(url, init, opts.timeoutMs || 8000);
}

function responseFor(check, byStep, last) {
  if (check.step == null) return last;
  return byStep.get(check.step) || null;
}

export async function runAuthoredSteps(input, opts = {}) {
  const parsed = asParsed(input);
  const runnableBlocks = parsed.blocks.filter(canRun);
  if (!parsed.present || runnableBlocks.length === 0) {
    const reason = parsed.blocks.find((block) => block.reason)?.reason || "no authored steps";
    return finish("inconclusive", parsed.present ? reason : "no authored steps", emptyEvidence(), false);
  }

  const observations = [];
  const success = [];
  const guards = [];
  let successFailed = false;
  let guardTripped = false;

  for (const block of runnableBlocks) {
    const byStep = new Map();
    let last = null;
    for (const request of block.requests) {
      const resolved = resolveRequestUrl(request, opts.baseUrl);
      if (resolved.error) {
        return finish("inconclusive", resolved.error, emptyEvidence({ executed: observations.length > 0, observations, success, falsePositiveGuard: guards }), true);
      }
      let url;
      try {
        url = new URL(resolved.url);
      } catch {
        return finish("inconclusive", "authored URL is not usable", emptyEvidence({ observations, success, falsePositiveGuard: guards }), true);
      }
      if (url.protocol !== "http:" && url.protocol !== "https:") {
        return finish("inconclusive", "authored URL is not usable", emptyEvidence({ observations, success, falsePositiveGuard: guards }), true);
      }
      const gate = scopeAllows(opts.scope || "", url.hostname);
      if (!gate.allowed) {
        return finish("inconclusive", "out of scope", emptyEvidence({ executed: observations.length > 0, observations, success, falsePositiveGuard: guards }), true);
      }
      let response;
      try {
        response = await doFetch(url.toString(), request, opts);
      } catch {
        return finish("inconclusive", "transport error", emptyEvidence({ observations, success, falsePositiveGuard: guards }), true);
      }
      if (!response || response.error || typeof response.status !== "number" || response.status === 0) {
        return finish("inconclusive", "transport error", emptyEvidence({ observations, success, falsePositiveGuard: guards }), true);
      }
      const observation = {
        step: request.step,
        method: request.method,
        url: url.toString(),
        status: response.status,
        bodyExcerpt: String(response.body || "").slice(0, 240),
      };
      observations.push(observation);
      byStep.set(request.step, response);
      last = response;
    }

    for (const check of block.success.checks) {
      const response = responseFor(check, byStep, last);
      if (!response || !check.matcher) {
        return finish("inconclusive", "success condition refers to a step that was not authored", emptyEvidence({ executed: true, observations, success, falsePositiveGuard: guards }), true);
      }
      const passed = matchSavedResponse(check.matcher, response) === true;
      success.push({ raw: check.raw, passed, step: check.step });
      if (!passed) successFailed = true;
    }
    for (const check of block.falsePositiveGuard?.checks || []) {
      const response = responseFor(check, byStep, last);
      if (!response || !check.matcher) {
        return finish("inconclusive", "false-positive guard refers to a step that was not authored", emptyEvidence({ executed: true, observations, success, falsePositiveGuard: guards }), true);
      }
      const tripped = matchSavedResponse(check.matcher, response) === true;
      guards.push({ raw: check.raw, tripped, step: check.step });
      if (tripped) guardTripped = true;
    }
  }

  const evidence = emptyEvidence({ executed: true, observations, success, falsePositiveGuard: guards });
  if (successFailed) return finish("not-confirmed", "authored success condition did not hold", evidence, true);
  if (guardTripped) return finish("not-confirmed", "false-positive guard matched", evidence, true);
  return finish("confirmed", "authored success condition held and false-positive guard did not match", evidence, true);
}
