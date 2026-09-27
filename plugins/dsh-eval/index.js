/**
 * dsh-eval — measure bughive's own detection quality.
 *
 * WHY THIS EXISTS
 * Every leader in this space attributes progress to benchmarking first. Without a
 * measurement loop, "improvements" to prompts, skills and plugins are unfalsifiable
 * opinions, and the tool cannot tell a regression from a win. This plugin is that loop.
 *
 * It ships a local vulnerable fixture (fixture-app.mjs, loopback-only) with a ground-truth
 * manifest, so a full precision/recall measurement runs offline with no Docker and no
 * external target. The point is not a leaderboard score -- it is that any change to the
 * pipeline can be shown to help or hurt, per vulnerability class.
 *
 * Scoring is deliberately strict:
 *   - a finding matching a planted bug by class AND path   -> true positive
 *   - a finding matching nothing in the manifest           -> false positive
 *   - a planted bug no finding matched                     -> false negative
 */

import { readFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export const name = "eval";
export const inject = ["tools"];

const HERE = dirname(fileURLToPath(import.meta.url));

/** Normalise a free-text class label to a canonical one using the manifest aliases. */
export function canonicalClass(label, aliases) {
  const l = String(label || "").toLowerCase().trim();
  for (const [canon, list] of Object.entries(aliases || {})) {
    if (canon === l) return canon;
    if (list.some((a) => l === a || l.includes(a))) return canon;
  }
  return l;
}

/**
 * Pure scoring core, exported for offline testing.
 * findings: [{class, path, method?}]   truth: the parsed ground-truth manifest
 */
export function score(findings, truth) {
  const aliases = truth.class_aliases || {};
  const bugs = truth.bugs || [];
  const used = new Set();
  const tps = [];
  const fps = [];

  for (const f of findings) {
    const c = canonicalClass(f.class, aliases);
    const path = String(f.path || "");
    const hit = bugs.find(
      (b, i) =>
        !used.has(i) &&
        canonicalClass(b.class, aliases) === c &&
        (path === b.path || path.startsWith(b.path_prefix) || b.path_prefix.startsWith(path.split("?")[0]))
    );
    if (hit) {
      used.add(bugs.indexOf(hit));
      tps.push({ finding: f, matched: hit.id, class: hit.class });
    } else {
      fps.push({ finding: f, reason: "no planted bug matches this class+path" });
    }
  }

  const fns = bugs.filter((_, i) => !used.has(i)).map((b) => ({ id: b.id, class: b.class, path: b.path }));

  const perClass = {};
  for (const b of bugs) {
    perClass[b.class] ||= { planted: 0, found: 0 };
    perClass[b.class].planted += 1;
  }
  for (const t of tps) {
    perClass[t.class] ||= { planted: 0, found: 0 };
    perClass[t.class].found += 1;
  }
  for (const k of Object.keys(perClass)) {
    const v = perClass[k];
    v.recall = v.planted ? Number((v.found / v.planted).toFixed(2)) : 0;
  }

  const tp = tps.length;
  const fp = fps.length;
  const fn = fns.length;
  const precision = tp + fp ? Number((tp / (tp + fp)).toFixed(3)) : 0;
  const recall = tp + fn ? Number((tp / (tp + fn)).toFixed(3)) : 0;
  const f1 = precision + recall ? Number(((2 * precision * recall) / (precision + recall)).toFixed(3)) : 0;

  return {
    planted: bugs.length,
    reported: findings.length,
    tp,
    fp,
    fn,
    precision,
    recall,
    f1,
    per_class: perClass,
    true_positives: tps,
    false_positives: fps,
    false_negatives: fns,
    verdict:
      tp === 0
        ? "Found nothing planted — detection is not working on this fixture."
        : fp > 0
          ? "Recall achieved but with false positives; a triager would reject part of this."
          : fn === 0
            ? "Clean sweep: every planted bug found, no noise."
            : `${fn} planted bug(s) missed.`,
  };
}

export function apply(ctx, config = {}) {
  const cfg = { fixture: join(HERE, "fixture-app.mjs"), truth: join(HERE, "ground-truth.json"), ...config };
  let child = null;
  let fixtureUrl = null;

  ctx.tools.register({
    name: "eval_scenarios",
    description:
      "Return the evaluation fixture's ground truth: every deliberately planted bug with its class, path and proof. Use this to see what a hunt is expected to find, or to score a run.",
    parameters: { type: "object", properties: {} },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute() {
      const truth = JSON.parse(await readFile(cfg.truth, "utf8"));
      return JSON.stringify({
        target: truth.target,
        planted: truth.bugs.length,
        classes: [...new Set(truth.bugs.map((b) => b.class))],
        bugs: truth.bugs,
      });
    },
  });

  ctx.tools.register({
    name: "eval_start_fixture",
    description:
      "Start the bundled vulnerable fixture on 127.0.0.1 (loopback only) and return its URL. This is a local benchmark target for measuring detection, not a real system.",
    parameters: {
      type: "object",
      properties: { port: { type: "number", description: "Port to bind (default 8099)." } },
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      if (child) return JSON.stringify({ already_running: true, url: fixtureUrl });
      const port = Number.isFinite(args.port) ? args.port : 8099;
      child = spawn(process.execPath, [cfg.fixture, "--port", String(port)], {
        stdio: ["ignore", "pipe", "pipe"],
      });
      fixtureUrl = `http://127.0.0.1:${port}`;
      const started = await new Promise((resolve) => {
        const timer = setTimeout(() => resolve(false), 6000);
        child.stdout.on("data", (d) => {
          if (String(d).includes("listening")) {
            clearTimeout(timer);
            resolve(true);
          }
        });
        child.on("exit", () => {
          clearTimeout(timer);
          resolve(false);
        });
      });
      if (!started) {
        child = null;
        return JSON.stringify({ started: false, error: "fixture did not report listening" });
      }
      return JSON.stringify({ started: true, url: fixtureUrl, pid: child.pid, bound: "127.0.0.1" });
    },
  });

  ctx.tools.register({
    name: "eval_stop_fixture",
    description: "Stop the evaluation fixture.",
    parameters: { type: "object", properties: {} },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute() {
      if (!child) return JSON.stringify({ stopped: false, note: "not running" });
      child.kill();
      child = null;
      fixtureUrl = null;
      return JSON.stringify({ stopped: true });
    },
  });

  ctx.tools.register({
    name: "eval_score",
    description:
      "Score a set of findings against the fixture ground truth. Returns true positives, false positives, false negatives, precision/recall/F1 and a per-class breakdown. Use this to prove a pipeline change actually helped rather than assuming it did.",
    parameters: {
      type: "object",
      properties: {
        findings: {
          type: "string",
          description: "JSON array of findings, each {class, path, method?}.",
        },
      },
      required: ["findings"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      let findings;
      try {
        findings = JSON.parse(args.findings);
        if (!Array.isArray(findings)) throw new Error("not an array");
      } catch (e) {
        return JSON.stringify({ error: `findings must be a JSON array: ${e.message}` });
      }
      const truth = JSON.parse(await readFile(cfg.truth, "utf8"));
      return JSON.stringify(score(findings, truth));
    },
  });

  console.log("[eval] registered: eval_scenarios, eval_start_fixture, eval_stop_fixture, eval_score");
}
