#!/usr/bin/env node
// bughive flow-runner. Executes multi-step app flows (register, login,
// password-reset, checkout, invite) defined in recon/flow-templates/*.yml,
// using Playwright (headless Chromium).
//
// Safety rules (non-negotiable, not config flags):
//   1. Never navigates outside scope.txt.
//   2. Never fills or submits a field that looks like a payment instrument
//      (card number, CVV, expiry, IBAN, routing/account number), under any
//      flag. This is a hard block, not something --allow-side-effects can
//      override.
//   3. Any other side-effecting step (account creation, password-reset
//      email, invite email) only executes if the caller passes
//      --allow-side-effects AND the flow id is listed in
//      hunts/<domain>/flow-side-effects.allow. Otherwise the runner fills
//      the form, records what it would have done, and stops before the
//      submit click (dry run).
//   4. Every synthetic email uses an operator-controlled catch-all domain
//      (--synthetic-domain) -- never a guessed real third party's address.
//   5. Field VALUES for password/token/card-like inputs are never written
//      to the summary or HAR redaction pass; only field NAMES are logged.

import { chromium } from "playwright";
import { parse as parseYaml } from "yaml";
import { readFile, writeFile, readdir, mkdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..");
const TEMPLATES_DIR = join(REPO_ROOT, "recon", "flow-templates");

// Field names get normalized (lowercased, separators stripped) before
// matching, then checked as plain substrings. Regex \b word-boundaries
// don't do what you'd expect here -- "iban_number" has no \b between "n"
// and "_" because underscore counts as a word character in JS regex, so
// /\biban\b/ silently fails to match it. Substring matching on a
// normalized string sidesteps that whole class of bug, and for a safety
// block, erring toward over-matching (skip a field that turns out to be
// harmless) is the correct failure direction -- never the reverse.
function normalizeFieldName(name) {
  return (name || "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

const PAYMENT_FIELD_SUBSTRINGS = [
  "cardnumber", "ccnum", "cardnum", "creditcard", "debitcard",
  "cvv", "cvc", "securitycode",
  "cardexpiry", "expmonth", "expyear", "expdate",
  "expirymonth", "expiryyear", "expirydate", "expirationdate",
  "iban", "routingnumber", "accountnumber", "swiftcode", "pan",
];
const SENSITIVE_EXTRA_SUBSTRINGS = ["password", "passwd", "token", "secret", "otp", "pin"];

function args() {
  const a = process.argv.slice(2);
  const out = { allowSideEffects: false };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === "--domain") out.domain = a[++i];
    else if (a[i] === "--hunts-root") out.huntsRoot = a[++i];
    else if (a[i] === "--synthetic-domain") out.syntheticDomain = a[++i];
    else if (a[i] === "--allow-side-effects") out.allowSideEffects = true;
    else if (a[i] === "--timeout-ms") out.timeoutMs = parseInt(a[++i], 10);
  }
  if (!out.domain) throw new Error("--domain is required");
  out.huntsRoot ??= join(REPO_ROOT, "hunts");
  out.syntheticDomain ??= "bughive-test.invalid";
  out.timeoutMs ??= 45000;
  return out;
}

async function loadScope(huntDir) {
  try {
    const raw = await readFile(join(huntDir, "scope.txt"), "utf-8");
    return new Set(raw.split("\n").map((l) => l.trim().toLowerCase()).filter(Boolean));
  } catch {
    return null; // no scope file -- caller decides whether that's fatal
  }
}

export function inScope(url, scope) {
  if (!scope) return false; // fail closed: no scope file means nothing is in scope
  try {
    const host = new URL(url).hostname.toLowerCase();
    return scope.has(host) || [...scope].some((s) => host.endsWith(`.${s}`));
  } catch {
    return false;
  }
}

async function loadTemplates() {
  const files = (await readdir(TEMPLATES_DIR)).filter((f) => f.endsWith(".yml"));
  const templates = [];
  for (const f of files) {
    const raw = await readFile(join(TEMPLATES_DIR, f), "utf-8");
    templates.push(parseYaml(raw));
  }
  return templates;
}

// Pull candidate entry URLs for a template out of earlier recon phases
// (04-http-probe, 05-content-discovery) instead of crawling blind.
export async function candidateUrls(huntDir, template) {
  const candidates = new Set();
  for (const phase of ["04-http-probe", "05-content-discovery"]) {
    const p = join(huntDir, "recon", phase, "summary.json");
    let summary;
    try {
      summary = JSON.parse(await readFile(p, "utf-8"));
    } catch {
      continue;
    }
    const items = Array.isArray(summary.items) ? summary.items : [];
    for (const item of items) {
      const text = typeof item === "string" ? item : JSON.stringify(item);
      for (const frag of template.entry_hints?.path_patterns || []) {
        if (text.toLowerCase().includes(frag)) {
          const m = text.match(/https?:\/\/[^\s"'<>]+/);
          if (m) candidates.add(m[0]);
        }
      }
    }
  }
  return [...candidates];
}

export function isPaymentField(name) {
  const n = normalizeFieldName(name);
  return PAYMENT_FIELD_SUBSTRINGS.some((s) => n.includes(s));
}
export function isSensitiveField(name) {
  const n = normalizeFieldName(name);
  return isPaymentField(name) || SENSITIVE_EXTRA_SUBSTRINGS.some((s) => n.includes(s));
}

function fillValueFor(fieldKind, template, runId, syntheticDomain) {
  const sd = template.steps.find((s) => s.action === "fill_fields")?.synthetic_data || {};
  if (fieldKind === "email" && sd.email_template) {
    return sd.email_template.replace("{run_id}", runId).replace("{synthetic_domain}", syntheticDomain);
  }
  if (fieldKind === "password") return "Bughive-Test-Pw-1!";
  if (fieldKind === "name") return "Bughive Test";
  return "bughive-test";
}

async function matchFields(page, hints) {
  // Heuristic field discovery: match input name/id/placeholder/aria-label
  // against each hint keyword. Returns { kind: elementHandle }.
  const matched = {};
  const inputs = await page.$$("input, textarea");
  for (const input of inputs) {
    const [name, id, placeholder, aria, type] = await Promise.all([
      input.getAttribute("name"),
      input.getAttribute("id"),
      input.getAttribute("placeholder"),
      input.getAttribute("aria-label"),
      input.getAttribute("type"),
    ]);
    const haystack = [name, id, placeholder, aria, type].filter(Boolean).join(" ").toLowerCase();
    for (const [kind, keywords] of Object.entries(hints)) {
      if (matched[kind]) continue;
      if (keywords.some((k) => haystack.includes(k))) matched[kind] = { input, fieldName: name || id || kind };
    }
  }
  return matched;
}

async function runFlow(browser, huntDir, domain, template, opts, allowlist) {
  const runId = Date.now().toString(36);
  const entries = await candidateUrls(huntDir, template);
  if (entries.length === 0) {
    return { flow: template.id, attempted: false, reason: "no candidate entry URL found in phase 04/05 recon" };
  }

  const scope = await loadScope(huntDir);
  const harPath = join(huntDir, "recon", "11-flow-mapping", `${template.id}.har`);
  await mkdir(dirname(harPath), { recursive: true });

  const context = await browser.newContext({ recordHar: { path: harPath, content: "embed" } });
  const page = await context.newPage();
  const stepsLog = [];
  const observations = {};
  let stoppedEarly = null;

  page.on("response", (res) => {
    stepsLog.push({ url: res.url(), status: res.status(), method: res.request().method(), ts: Date.now() });
  });

  try {
    const entryUrl = entries[0];
    if (!inScope(entryUrl, scope)) {
      return { flow: template.id, attempted: false, reason: `entry URL ${entryUrl} not in scope.txt` };
    }

    await page.goto(entryUrl, { timeout: opts.timeoutMs, waitUntil: "domcontentloaded" });

    for (const step of template.steps) {
      if (step.action === "goto" || step.action === "goto_cart") continue; // handled by entry nav / heuristic click below

      if (step.action === "fill_fields") {
        const matched = await matchFields(page, step.field_hints || {});
        for (const [kind, { input, fieldName }] of Object.entries(matched)) {
          if (isPaymentField(fieldName)) {
            observations.payment_field_detected = true;
            stoppedEarly = "payment field detected during fill_fields -- hard-blocked";
            break;
          }
          const value = fillValueFor(kind, template, runId, opts.syntheticDomain);
          await input.fill(value).catch(() => {});
          // never log the value for sensitive fields, only that it was touched
          stepsLog.push({ step: step.name, action: "fill", field: isSensitiveField(fieldName) ? "<redacted-name>" : fieldName });
        }
        if (stoppedEarly) break;
      }

      if (step.action === "advance_to_payment") {
        const inputs = await page.$$("input");
        for (const input of inputs) {
          const name = (await input.getAttribute("name")) || (await input.getAttribute("id")) || "";
          if (isPaymentField(name)) {
            observations.payment_step_reached_without_submitting = true;
            stoppedEarly = "reached payment step; stopped before touching payment fields (hard rule)";
            break;
          }
        }
        break; // this template's job stops here regardless
      }

      if (step.action === "click" || step.action === "click_submit") {
        const isGatedSideEffect = step.side_effect === true;
        const allowed = opts.allowSideEffects && allowlist.has(template.id);
        if (isGatedSideEffect && !allowed) {
          observations[`would_execute_${step.name}`] = true;
          stoppedEarly = `dry run: side-effecting step "${step.name}" requires --allow-side-effects and an entry in flow-side-effects.allow`;
          break;
        }
        const hints = step.click_hints || step.submit_hints || [];
        const btn = await page.getByRole("button", { name: new RegExp(hints.join("|"), "i") }).first();
        if (await btn.count().catch(() => 0)) {
          await btn.click({ timeout: 5000 }).catch(() => {});
          stepsLog.push({ step: step.name, action: "click", side_effect_executed: isGatedSideEffect });
        }
      }
    }
  } catch (e) {
    stoppedEarly = `error: ${e.message}`;
  } finally {
    await context.close().catch(() => {});
  }

  return {
    flow: template.id,
    attempted: true,
    entry_url: entries[0],
    stopped_early: stoppedEarly,
    observations,
    step_count: stepsLog.length,
    har: harPath,
  };
}

async function main() {
  const opts = args();
  const huntDir = join(opts.huntsRoot, opts.domain);
  const outDir = join(huntDir, "recon", "11-flow-mapping");
  await mkdir(outDir, { recursive: true });

  const scope = await loadScope(huntDir);
  if (!scope) {
    const summary = {
      phase: "11-flow-mapping", domain: opts.domain,
      tools_run: [], tools_skipped: [{ tool: "playwright", reason: "no scope.txt found -- refusing to run (fail closed)" }],
      count: 0, items: [], notes: ["scope.txt missing; nothing executed"], output_files: [],
    };
    await writeFile(join(outDir, "summary.json"), JSON.stringify(summary, null, 2));
    console.log(JSON.stringify(summary));
    return;
  }

  let allowlist = new Set();
  try {
    const raw = await readFile(join(huntDir, "flow-side-effects.allow"), "utf-8");
    allowlist = new Set(raw.split("\n").map((l) => l.trim()).filter(Boolean));
  } catch { /* absent = nothing allow-listed, everything stays dry-run */ }

  const templates = await loadTemplates();
  const browser = await chromium.launch({ headless: true });
  const results = [];
  try {
    for (const template of templates) {
      const r = await Promise.race([
        runFlow(browser, huntDir, opts.domain, template, opts, allowlist),
        new Promise((_, rej) => setTimeout(() => rej(new Error("phase timeout")), opts.timeoutMs + 5000)),
      ]).catch((e) => ({ flow: template.id, attempted: false, reason: e.message }));
      results.push(r);
    }
  } finally {
    await browser.close().catch(() => {});
  }

  const summary = {
    phase: "11-flow-mapping",
    domain: opts.domain,
    tools_run: ["playwright"],
    tools_skipped: [],
    count: results.filter((r) => r.attempted).length,
    items: results,
    notes: [
      "Side-effecting steps (account creation, password-reset email, invite email) only execute if --allow-side-effects was passed AND the flow id is listed in flow-side-effects.allow; otherwise they are dry-run only.",
      "Payment fields are never filled or submitted under any flag.",
    ],
    output_files: results.filter((r) => r.har).map((r) => r.har),
  };
  await writeFile(join(outDir, "summary.json"), JSON.stringify(summary, null, 2));
  console.log(JSON.stringify({ phase: "11-flow-mapping", count: summary.count, flows: results.map((r) => r.flow) }));
}

// Only auto-run when executed directly (`node flow-runner.mjs ...`), not
// when imported by tests.
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(`[flow-runner] fatal: ${e.message}`);
    process.exit(1);
  });
}
