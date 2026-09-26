#!/usr/bin/env node
/**
 * JEV decision stage.
 *
 * JEV (TypeSafe System One) does not write hypotheses. It answers typed
 * questions about the recon state: what to do next, which skill, which
 * vulnerability, and which test method. This script applies hunt policy
 * (legal stage order, confidence floor, human gate) and writes
 * hunts/<domain>/jev-decision.json. The parent orchestrator follows that
 * file; it does not re-decide.
 *
 * Auth: TYPESAFE_API_KEY (Bearer). Optional TYPESAFE_MODEL (default
 * jev-latest). Optional TYPESAFE_API_BASE for tests.
 *
 *   node scripts/pipeline/jev-decide.mjs <domain>
 *   node scripts/pipeline/jev-decide.mjs --selftest
 */

import { readFile, writeFile, readdir, mkdir, copyFile } from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const HUNTS = join(ROOT, "hunts");
const SKILLS = join(ROOT, "skills");

const API_URL =
  process.env.TYPESAFE_API_BASE || "https://api.typesafe.ai/v1/systemone";
const MODEL = process.env.TYPESAFE_MODEL || "jev-latest";

const CONFIDENCE_FLOOR = 0.45;
const HUMAN_REVIEW_CEILING = 0.7;
const WORTH_TESTING_FLOOR = 0.35;
const SKILL_PROB_FLOOR = 0.08;
const SKILL_LOAD_FLOOR = 0.4;
const MAX_SKILLS = 8;
const CONFIRM_TOP = 3;
const STATE_BUDGET = 24000;

const HIGH_SIGNAL = [
  "14-nuclei-scan",
  "15-mass-oneliners",
  "13-secret-scan",
  "17-interesting-endpoints",
  "16-github-dorking",
  "11-flow-mapping",
  "06-param-discovery",
  "07-js-analysis",
  "08-tech-fingerprint",
];

const NEXT_ACTIONS = {
  deepen_recon:
    "A high-signal recon phase is missing or empty. Run that phase before testing.",
  select_and_test:
    "Load the chosen skills and run hypothesis generation only for the chosen vulnerability and test method.",
  falsify:
    "Hypotheses already exist. Run prefilter and the falsifier. Do not generate more.",
  prove: "Falsifier survivors exist. Run the proof validator.",
  chain: "Validated findings exist. Build a chain.",
  report: "Validated findings are ready to write up.",
  human_gate: "Stop and ask the human before any further testing.",
  stop: "No concrete test. End the hunt and write SUMMARY.md.",
};

const TEST_METHODS = {
  checklist_walk:
    "Walk the chosen skill's numbered techniques against one cited recon item.",
  tool_hit_falsify:
    "A phase 13, 14, 15, or 16 hit exists. Do not re-derive it. Send it to the falsifier.",
  flow_step_skip:
    "Phase 11 mapped a multi-step flow. Request a later step directly.",
  auth_swap:
    "Repeat one discovered request with a second identity or an id/role swap named in the skill.",
  param_mutation:
    "Change one discovered parameter using only a technique listed in the chosen skill.",
  version_match:
    "Phase 08 fingerprinted a technology the skill calls out. Run that version-specific check only.",
  hold: "Evidence is too thin. Do not open a hypothesis.",
};

export function sanitizeDomain(raw) {
  let d = String(raw || "").trim();
  d = d.replace(/^https?:\/\//, "");
  d = d.split("/")[0].split(":")[0];
  return d.toLowerCase();
}

function loadDotEnv() {
  const path = join(ROOT, ".env");
  if (!existsSync(path) || process.env.TYPESAFE_API_KEY) return;
  for (const line of readFileSync(path, "utf8").split("\n")) {
    const m = line.match(/^\s*TYPESAFE_API_KEY\s*=\s*(.*)\s*$/);
    if (!m) continue;
    let v = m[1].trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
      v = v.slice(1, -1);
    }
    if (v) process.env.TYPESAFE_API_KEY = v;
  }
}

function compact(value, depth = 0) {
  if (value == null) return undefined;
  if (typeof value === "string") {
    return value.length > 400 ? `${value.slice(0, 400)}…` : value;
  }
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (depth > 3) return undefined;
  if (Array.isArray(value)) {
    return value
      .slice(0, 8)
      .map((v) => compact(v, depth + 1))
      .filter((v) => v !== undefined);
  }
  if (typeof value === "object") {
    const out = {};
    for (const k of Object.keys(value).slice(0, 24)) {
      if (k === "output_files" || k === "body" || k === "raw" || k === "response_body") continue;
      const c = compact(value[k], depth + 1);
      if (c !== undefined) out[k] = c;
    }
    return out;
  }
  return undefined;
}

async function readJson(path) {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch {
    return null;
  }
}

async function fileExists(path) {
  try {
    await readFile(path);
    return true;
  } catch {
    return false;
  }
}

export async function loadSkills() {
  const skills = [];
  for (const sub of ["seeds", "learned"]) {
    let names = [];
    try {
      names = await readdir(join(SKILLS, sub));
    } catch {
      continue;
    }
    for (const name of names) {
      if (!name.endsWith(".md") || name === "bughunter.md") continue;
      const id = `${sub}/${name.replace(/\.md$/, "")}`;
      const body = await readFile(join(SKILLS, sub, name), "utf8");
      const lines = body
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean)
        .filter((l) => !l.startsWith("```"));
      const blurb = lines.slice(0, 6).join(" ").replace(/\s+/g, " ").slice(0, 160);
      skills.push({ id, key: id.replaceAll("/", "__"), blurb });
    }
  }
  return skills;
}

async function huntSnapshot(domain) {
  const hd = join(HUNTS, sanitizeDomain(domain));
  const stateDir = join(hd, ".state");
  let done = [];
  try {
    done = (await readdir(stateDir)).filter((f) => f.endsWith(".done")).map((f) => f.replace(/\.done$/, ""));
  } catch {
    /* hunt not initialised */
  }

  const recon = {};
  const reconRoot = join(hd, "recon");
  let phaseNames = [];
  try {
    phaseNames = await readdir(reconRoot);
  } catch {
    phaseNames = [];
  }
  for (const phase of phaseNames) {
    const summaryPath = join(reconRoot, phase, "summary.json");
    const raw = await readJson(summaryPath);
    if (raw) recon[phase] = compact(raw);
    else if (await fileExists(summaryPath)) {
      const text = await readFile(summaryPath, "utf8");
      recon[phase] = text.slice(0, 1500);
    }
  }

  const present = new Set(phaseNames.filter((p) => recon[p]));
  const missing = HIGH_SIGNAL.filter((p) => !present.has(p));

  const keyword = (await readJson(join(hd, "skills-keyword.json"))) ||
    (await readJson(join(hd, "skills-selected.json"))) ||
    [];

  const counts = {};
  for (const [label, file] of [
    ["hypotheses", "hypotheses.json"],
    ["hypotheses_pass", "hypotheses-pass.json"],
    ["hypotheses_real", "hypotheses-real.json"],
    ["validated", "validated.json"],
  ]) {
    const data = await readJson(join(hd, file));
    counts[label] = Array.isArray(data) ? data.length : 0;
  }

  return { hd, done, recon, missing, keyword, counts };
}

function buildState(snap, skills) {
  const keywordLines = (Array.isArray(snap.keyword) ? snap.keyword : [])
    .slice(0, 8)
    .map((s) => `${s.skill} score=${s.score} terms=${s.matched_terms || ""}`)
    .join("\n");

  let reconText = "";
  for (const phase of Object.keys(snap.recon)) {
    const chunk = `## ${phase}\n${JSON.stringify(snap.recon[phase])}\n`;
    if (reconText.length + chunk.length > STATE_BUDGET) {
      reconText += `## ${phase}\n(omitted, state budget)\n`;
      continue;
    }
    reconText += chunk;
  }

  return [
    "Bug bounty hunt state. Decide only from this evidence.",
    `stages_done: ${snap.done.join(", ") || "(none)"}`,
    `missing_high_signal_phases: ${snap.missing.join(", ") || "(none)"}`,
    `artifact_counts: hypotheses=${snap.counts.hypotheses} pass=${snap.counts.hypotheses_pass} real=${snap.counts.hypotheses_real} validated=${snap.counts.validated}`,
    "Keyword overlap shortlist (evidence, not a decision):",
    keywordLines || "(none)",
    "Skill catalog:",
    skills.map((s) => `${s.key}: ${s.blurb}`).join("\n"),
    "Recon summaries:",
    reconText || "(no recon yet)",
  ].join("\n");
}

function focusOptions(snap) {
  const urls = [];
  const push = (url) => {
    if (typeof url !== "string" || !/^https?:\/\//i.test(url)) return;
    if (!urls.includes(url)) urls.push(url);
  };
  const walk = (node, depth = 0) => {
    if (depth > 4 || urls.length >= 12) return;
    if (typeof node === "string") push(node);
    else if (Array.isArray(node)) node.forEach((n) => walk(n, depth + 1));
    else if (node && typeof node === "object") {
      if (typeof node.url === "string") push(node.url);
      for (const v of Object.values(node)) walk(v, depth + 1);
    }
  };
  for (const phase of ["17-interesting-endpoints", "14-nuclei-scan", "15-mass-oneliners", "06-param-discovery"]) {
    if (snap.recon[phase]) walk(snap.recon[phase]);
  }
  const criteria = { none: "No single URL. Test the class against the cited recon item." };
  urls.slice(0, 12).forEach((url, i) => {
    criteria[`u${i}`] = url;
  });
  return { criteria, urls };
}

function routingQuestions(snap) {
  const phaseCriteria = {};
  for (const phase of snap.missing) phaseCriteria[phase.replaceAll("-", "_")] = `Run recon phase ${phase}`;
  if (Object.keys(phaseCriteria).length === 0) {
    phaseCriteria.none = "Every high-signal recon phase already has a summary.";
  }
  const questions = {
    next_action: {
      type: "choice",
      instructions:
        "Given stages already done and the recon evidence, what should the hunt do next?",
      criteria: Object.fromEntries(
        Object.entries(NEXT_ACTIONS).map(([k, v]) => [k, v]),
      ),
    },
    recon_phase: {
      type: "choice",
      instructions: "If more recon is warranted, which missing phase is the one to run?",
      criteria: phaseCriteria,
    },
    signal: {
      type: "score",
      instructions: "How strong is the attack-surface evidence in this recon?",
      criteria: [
        "no attack surface",
        "thin hints only",
        "a specific parameter or endpoint to test",
        "a tool-confirmed hit",
        "a critical exposure is already visible",
      ],
    },
    worth_testing: {
      type: "noul",
      instructions: "Is there a concrete vulnerability test worth running on this evidence?",
    },
    human_review: {
      type: "noul",
      instructions: "Should a human review this before any further testing?",
    },
  };
  return questions;
}

function skillQuestion(skills) {
  const criteria = {};
  for (const s of skills) criteria[s.key] = s.blurb || s.id;
  return {
    skill: {
      type: "choice",
      instructions:
        "Which single skill is the best first vulnerability class to test on this recon? Rank by fit to the evidence, not by severity in the abstract.",
      criteria,
    },
  };
}

function confirmQuestions(top, snap) {
  const questions = {};
  top.forEach((s, i) => {
    questions[`load_${i}`] = {
      type: "noul",
      instructions: `Load skill ${s.id} for this target? Only yes if recon evidence matches that skill.`,
    };
  });
  const vulnCriteria = {};
  for (const s of top) vulnCriteria[s.key] = s.blurb || s.id;
  questions.vuln = {
    type: "choice",
    instructions: "Of these candidate skills, which vulnerability should be tested first?",
    criteria: vulnCriteria,
  };
  questions.test_method = {
    type: "choice",
    instructions: "How should that vulnerability be tested, given the evidence on hand?",
    criteria: TEST_METHODS,
  };
  const focus = focusOptions(snap);
  questions.focus = {
    type: "choice",
    instructions: "Which URL should that test focus on?",
    criteria: focus.criteria,
  };
  return { questions, focus };
}

export async function jevCall(state, questions, fetchImpl = globalThis.fetch) {
  const key = process.env.TYPESAFE_API_KEY;
  if (!key) {
    const err = new Error(
      "TYPESAFE_API_KEY is not set. JEV decisions require a TypeSafe API key.",
    );
    err.code = "NO_KEY";
    throw err;
  }
  const res = await fetchImpl(API_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ model: MODEL, state, questions }),
    signal: AbortSignal.timeout(45000),
  });
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = { raw: text.slice(0, 500) };
  }
  if (!res.ok) {
    const err = new Error(`JEV HTTP ${res.status}: ${text.slice(0, 400)}`);
    err.code = "HTTP";
    err.status = res.status;
    err.body = body;
    throw err;
  }
  const answers = body.answers || body.data?.answers;
  if (!answers || typeof answers !== "object") {
    const err = new Error("JEV response had no answers object");
    err.code = "SHAPE";
    err.body = body;
    throw err;
  }
  return { model: body.model || MODEL, answers, usage: body.usage || body.data?.usage || null };
}

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

function choiceOf(answer) {
  if (!answer || typeof answer !== "object") return { choice: null, confidence: 0, probabilities: {} };
  return {
    choice: answer.choice ?? answer.value ?? null,
    confidence: num(answer.confidence),
    probabilities: answer.probabilities || {},
  };
}

function rankedSkills(probabilities, skills) {
  const byKey = new Map(skills.map((s) => [s.key, s]));
  return Object.entries(probabilities)
    .map(([key, p]) => ({ ...(byKey.get(key) || { id: key, key, blurb: "" }), probability: num(p) }))
    .filter((s) => s.id.includes("/"))
    .sort((a, b) => b.probability - a.probability);
}

function nearestSignal(scoreAnswer) {
  const criteria = [
    "no attack surface",
    "thin hints only",
    "a specific parameter or endpoint to test",
    "a tool-confirmed hit",
    "a critical exposure is already visible",
  ];
  const score = num(scoreAnswer?.score);
  const idx = Math.max(0, Math.min(criteria.length - 1, Math.round(score)));
  return { score, label: scoreAnswer?.legend?.[String(idx)] || criteria[idx] };
}

function keywordScore(snap, id) {
  const row = (Array.isArray(snap.keyword) ? snap.keyword : []).find((s) => s.skill === id);
  return row || null;
}

function urgentToolHit(snap) {
  const nuclei = snap.recon["14-nuclei-scan"];
  if (nuclei && typeof nuclei === "object" && Array.isArray(nuclei.items)) {
    if (nuclei.items.some((it) => /^(critical|high)$/i.test(String(it?.severity || "")))) return true;
  }
  const oneliners = snap.recon["15-mass-oneliners"];
  if (oneliners && typeof oneliners === "object") {
    if (num(oneliners.count) > 0) return true;
    if (Array.isArray(oneliners.items) && oneliners.items.length > 0) return true;
  }
  return false;
}

function hasToolHit(snap) {
  for (const phase of ["13-secret-scan", "14-nuclei-scan", "15-mass-oneliners", "16-github-dorking"]) {
    const summary = snap.recon[phase];
    if (!summary || typeof summary !== "object") continue;
    if (num(summary.count) > 0) return true;
    if (Array.isArray(summary.items) && summary.items.length > 0) return true;
  }
  return false;
}

/**
 * Turn raw JEV answers into the one action the orchestrator must follow.
 * routing = first call, confirm = second call or null when testing is skipped.
 */
export function applyPolicy({ snap, skills, routing, confirm }, { routingOnly = false } = {}) {
  const next = choiceOf(routing.answers.next_action);
  const phase = choiceOf(routing.answers.recon_phase);
  const skillChoice = choiceOf(routing.answers.skill);
  const worth = num(routing.answers.worth_testing?.noul);
  const human = num(routing.answers.human_review?.noul);
  const signal = nearestSignal(routing.answers.signal);
  const ranked = rankedSkills(skillChoice.probabilities, skills);

  let action = next.choice && NEXT_ACTIONS[next.choice] ? next.choice : "human_gate";
  let clampedFrom = null;
  const untouched = snap.counts.hypotheses === 0 && snap.counts.validated === 0;
  if (urgentToolHit(snap) && untouched) {
    clampedFrom = action === "human_gate" ? null : action;
    action = "human_gate";
  }
  const clamp = (to) => {
    if (action !== to) clampedFrom = action;
    action = to;
  };

  const phaseKey = (phase.choice || "").replaceAll("_", "-");
  const reconPhase = snap.missing.includes(phaseKey) ? phaseKey : snap.missing[0] || null;

  if (next.confidence < CONFIDENCE_FLOOR) clamp("human_gate");
  if (human > HUMAN_REVIEW_CEILING) clamp("human_gate");

  const toolHit = hasToolHit(snap);
  if (toolHit && (action === "stop" || action === "deepen_recon")) clamp("select_and_test");

  if (action === "deepen_recon" && !reconPhase) clamp("select_and_test");
  if (action === "falsify" && snap.counts.hypotheses === 0) clamp("select_and_test");
  if (action === "prove" && snap.counts.hypotheses_real === 0) {
    clamp(snap.counts.hypotheses > 0 ? "falsify" : "select_and_test");
  }
  if ((action === "chain" || action === "report") && snap.counts.validated === 0) {
    if (snap.counts.hypotheses_real > 0) clamp("prove");
    else if (snap.counts.hypotheses > 0) clamp("falsify");
    else clamp("select_and_test");
  }
  if (action === "select_and_test" && worth < WORTH_TESTING_FLOOR && !toolHit) {
    clamp(reconPhase ? "deepen_recon" : "stop");
  }

  let kept = [];
  let vuln = null;
  let testMethod = "hold";
  let testConfidence = 0;
  let focusUrl = "none";
  let focusLabel = "none";

  if (confirm) {
    const top = ranked.slice(0, CONFIRM_TOP);
    kept = top.map((s, i) => {
      const noul = num(confirm.answers[`load_${i}`]?.noul);
      const kw = keywordScore(snap, s.id);
      const load = noul >= SKILL_LOAD_FLOOR && (s.probability >= SKILL_PROB_FLOOR || noul >= 0.6);
      return {
        skill: s.id,
        probability: s.probability,
        load_noul: noul,
        load,
        score: kw ? num(kw.score) : 0,
        matched_terms: kw?.matched_terms || "",
        reason: "jev probability plus confirm noul",
      };
    });
    const loaded = kept.filter((s) => s.load);
    const vulnChoice = choiceOf(confirm.answers.vuln);
    const methodChoice = choiceOf(confirm.answers.test_method);
    testMethod = TEST_METHODS[methodChoice.choice] ? methodChoice.choice : "hold";
    testConfidence = methodChoice.confidence;
    const focusChoice = choiceOf(confirm.answers.focus);
    focusLabel = focusChoice.choice || "none";
    if (focusLabel.startsWith("u")) {
      const idx = Number(focusLabel.slice(1));
      focusUrl = confirm.focus.urls[idx] || "none";
    } else {
      focusUrl = "none";
    }
    const vulnSkill = skills.find((s) => s.key === vulnChoice.choice);
    vuln = loaded.find((s) => s.skill === vulnSkill?.id)?.skill || loaded[0]?.skill || null;

    if (action === "select_and_test" && !vuln) {
      clamp(reconPhase ? "deepen_recon" : "stop");
    }
    if (testMethod === "hold" && action === "select_and_test") {
      clamp(reconPhase ? "deepen_recon" : "stop");
    }
  } else if (!routingOnly && action === "select_and_test") {
    clamp(reconPhase ? "deepen_recon" : "stop");
  }

  if (action !== "select_and_test") {
    testMethod = action === "falsify" || action === "prove" ? "tool_hit_falsify" : "hold";
  }

  const primary = vuln || kept.find((s) => s.load)?.skill || null;
  const instruction = [
    NEXT_ACTIONS[action],
    primary ? `Skill: ${primary}.` : "",
    action === "select_and_test" ? `Test method: ${testMethod}. ${TEST_METHODS[testMethod]}` : "",
    action === "select_and_test" && focusUrl !== "none" ? `Focus: ${focusUrl}.` : "",
    action === "deepen_recon" && reconPhase ? `Phase: ${reconPhase}.` : "",
    clampedFrom ? `Clamped from JEV's ${clampedFrom} by hunt policy.` : "",
  ]
    .filter(Boolean)
    .join(" ");

  return {
    model: confirm?.model || routing.model,
    source: "jev",
    next_action: action,
    clamped_from: clampedFrom,
    confidence: next.confidence,
    human_review: human,
    worth_testing: worth,
    signal_score: signal.score,
    signal_label: signal.label,
    recon_phase: action === "deepen_recon" ? reconPhase : null,
    skill: primary,
    skills: kept.filter((s) => s.load),
    skill_shortlist: ranked.slice(0, 5).map((s) => ({ skill: s.id, probability: s.probability })),
    vuln: primary,
    test_method: testMethod,
    test_method_note: TEST_METHODS[testMethod] || "",
    test_method_confidence: testConfidence,
    focus_url: focusUrl,
    focus_choice: focusLabel,
    instruction,
    usage: {
      routing: routing.usage,
      confirm: confirm?.usage || null,
    },
  };
}

async function writeDecision(snap, decision) {
  await mkdir(snap.hd, { recursive: true });
  const selectedPath = join(snap.hd, "skills-selected.json");
  const keywordPath = join(snap.hd, "skills-keyword.json");
  if (existsSync(selectedPath) && !existsSync(keywordPath)) {
    await copyFile(selectedPath, keywordPath);
  }
  const selected = (decision.skills || []).map((s) => ({
    skill: s.skill,
    score: s.score,
    probability: s.probability,
    load_noul: s.load_noul,
    matched_terms: s.matched_terms,
    reason: s.reason,
  }));
  await writeFile(selectedPath, `${JSON.stringify(selected, null, 2)}\n`);
  const out = { ...decision, created_at: new Date().toISOString() };
  await writeFile(join(snap.hd, "jev-decision.json"), `${JSON.stringify(out, null, 2)}\n`);
  return out;
}

export async function decide(domain, { fetchImpl } = {}) {
  loadDotEnv();
  const snap = await huntSnapshot(domain);
  if (!existsSync(snap.hd)) {
    throw new Error(`Hunt directory does not exist: ${snap.hd}. Run init first.`);
  }
  const skills = await loadSkills();
  if (skills.length === 0) throw new Error("No skills found under skills/seeds or skills/learned");

  const state = buildState(snap, skills);
  const routing = await jevCall(
    state,
    { ...routingQuestions(snap), ...skillQuestion(skills) },
    fetchImpl,
  );

  const probe = applyPolicy({ snap, skills, routing, confirm: null }, { routingOnly: true });
  let confirm = null;
  if (probe.next_action === "select_and_test" || probe.next_action === "deepen_recon") {
    const top = rankedSkills(choiceOf(routing.answers.skill).probabilities, skills).slice(0, CONFIRM_TOP);
    if (top.length > 0 && probe.next_action === "select_and_test") {
      const built = confirmQuestions(top, snap);
      const skillBodies = [];
      for (const s of top) {
        const body = await readFile(join(SKILLS, `${s.id}.md`), "utf8");
        skillBodies.push(`--- ${s.id} ---\n${body.slice(0, 3500)}`);
      }
      confirm = await jevCall(
        `${state}\n\nTop skill texts:\n${skillBodies.join("\n")}`,
        built.questions,
        fetchImpl,
      );
      confirm.focus = built.focus;
    }
  }

  const decision = applyPolicy({ snap, skills, routing, confirm });
  return writeDecision(snap, decision);
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

export async function selftest() {
  const skills = [
    { id: "seeds/idor", key: "seeds__idor", blurb: "swap object ids" },
    { id: "seeds/xss", key: "seeds__xss", blurb: "reflected script" },
    { id: "seeds/ssrf", key: "seeds__ssrf", blurb: "server-side fetch" },
  ];
  const baseSnap = {
    hd: "/tmp/jev-unused",
    done: ["scope", "recon-06"],
    recon: { "06-param-discovery": { count: 3, items: [{ url: "https://app.example/api/users?id=1" }] } },
    missing: ["14-nuclei-scan"],
    keyword: [{ skill: "seeds/idor", score: 4, matched_terms: "userid" }],
    counts: { hypotheses: 0, hypotheses_pass: 0, hypotheses_real: 0, validated: 0 },
  };
  const routing = {
    model: "jev-test",
    usage: { input_tokens: 10 },
    answers: {
      next_action: { choice: "select_and_test", confidence: 0.9, probabilities: {} },
      recon_phase: { choice: "14_nuclei_scan", confidence: 0.5, probabilities: {} },
      signal: { score: 2.2, confidence: 0.8 },
      worth_testing: { noul: 0.8 },
      human_review: { noul: 0.1 },
      skill: {
        choice: "seeds__idor",
        confidence: 0.7,
        probabilities: { seeds__idor: 0.62, seeds__xss: 0.3, seeds__ssrf: 0.08 },
      },
    },
  };
  const confirm = {
    model: "jev-test",
    usage: null,
    focus: { urls: ["https://app.example/api/users?id=1"] },
    answers: {
      load_0: { noul: 0.81 },
      load_1: { noul: 0.2 },
      load_2: { noul: 0.1 },
      vuln: { choice: "seeds__idor", confidence: 0.8, probabilities: {} },
      test_method: { choice: "auth_swap", confidence: 0.77, probabilities: {} },
      focus: { choice: "u0", confidence: 0.9, probabilities: {} },
    },
  };

  const ok = applyPolicy({ snap: baseSnap, skills, routing, confirm });
  assert(ok.next_action === "select_and_test", "expected select_and_test");
  assert(ok.skill === "seeds/idor", "expected idor");
  assert(ok.test_method === "auth_swap", "expected auth_swap");
  assert(ok.focus_url.includes("/api/users"), "expected focus url");
  assert(ok.skills.length === 1, "xss and ssrf below load floor");

  const low = applyPolicy({
    snap: baseSnap,
    skills,
    routing: {
      ...routing,
      answers: {
        ...routing.answers,
        next_action: { choice: "select_and_test", confidence: 0.2, probabilities: {} },
      },
    },
    confirm,
  });
  assert(low.next_action === "human_gate", "low confidence must gate");

  const review = applyPolicy({
    snap: baseSnap,
    skills,
    routing: {
      ...routing,
      answers: { ...routing.answers, human_review: { noul: 0.91 } },
    },
    confirm,
  });
  assert(review.next_action === "human_gate", "human review must gate");

  const earlyChain = applyPolicy(
    {
      snap: baseSnap,
      skills,
      routing: {
        ...routing,
        answers: {
          ...routing.answers,
          next_action: { choice: "chain", confidence: 0.95, probabilities: {} },
        },
      },
      confirm: null,
    },
    { routingOnly: true },
  );
  assert(earlyChain.next_action === "select_and_test", "chain without findings clamps forward");
  assert(earlyChain.clamped_from === "chain", "records clamp");

  const thin = applyPolicy({
    snap: baseSnap,
    skills,
    routing: {
      ...routing,
      answers: {
        ...routing.answers,
        worth_testing: { noul: 0.1 },
        next_action: { choice: "select_and_test", confidence: 0.8, probabilities: {} },
      },
    },
    confirm,
  });
  assert(thin.next_action === "deepen_recon", "thin evidence deepens recon");
  assert(thin.recon_phase === "14-nuclei-scan", "picks missing phase");

  const rejected = applyPolicy({
    snap: { ...baseSnap, missing: [] },
    skills,
    routing,
    confirm: {
      ...confirm,
      answers: { ...confirm.answers, load_0: { noul: 0.1 }, test_method: { choice: "hold", confidence: 0.6, probabilities: {} } },
    },
  });
  assert(rejected.next_action === "stop", "rejected skills and no missing phase stops");

  const urgent = applyPolicy({
    snap: {
      ...baseSnap,
      recon: {
        ...baseSnap.recon,
        "14-nuclei-scan": { count: 1, items: [{ severity: "high", template: "cve" }] },
      },
    },
    skills,
    routing,
    confirm,
  });
  assert(urgent.next_action === "human_gate", "high nuclei hit gates before testing");

  console.log(JSON.stringify({ selftest: "ok", cases: 7 }));
}

const invokedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  const arg = process.argv[2];
  if (arg === "--selftest") {
    selftest().catch((err) => {
      console.error(err.message || err);
      process.exit(1);
    });
  } else if (!arg) {
    console.error("usage: jev-decide.mjs <domain> | --selftest");
    process.exit(1);
  } else {
    decide(arg)
      .then((out) => {
        console.log(
          JSON.stringify({
            phase: "decide",
            next_action: out.next_action,
            skill: out.skill,
            vuln: out.vuln,
            test_method: out.test_method,
            focus_url: out.focus_url,
            confidence: out.confidence,
            file: join(HUNTS, sanitizeDomain(arg), "jev-decision.json"),
          }),
        );
      })
      .catch((err) => {
        console.error(err.message || err);
        process.exit(err.code === "NO_KEY" ? 2 : 1);
      });
  }
}
