/**
 * dsh-coverage — vuln-class x asset coverage matrix.
 *
 * WHY THIS EXISTS
 * The pipeline tracked recon phases and hypothesis counts but never what was actually
 * TESTED. So a hunt could legitimately reach the `deliver` stage and print "no findings"
 * while entire vulnerability classes and whole assets had never been touched. That is the
 * single easiest way to produce a false negative: not a wrong answer, but an unasked
 * question.
 *
 * This makes the untested surface explicit. A cell is `untested` by default, and may only
 * leave that state with evidence attached. `n/a` and `blocked` REQUIRE a reason, which
 * forces the honest answer ("needs a second account") instead of silent omission.
 *
 * The `coverage_gate` tool is the enforcement point: it fails while critical classes
 * remain untested, so "no bugs found" can only be claimed after the matrix says so.
 */

import { mkdir, readFile, writeFile, readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const name = "coverage";
export const inject = ["tools"];

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..");

/** Classes that must be resolved before a hunt may claim completeness. */
export const CRITICAL_CLASSES = [
  "idor",
  "unauth-api",
  "business-logic",
  "open-redirect",
  "subdomain-takeover",
  "host-header-injection",
  "cache-poisoning",
  "account-takeover",
  "oauth",
  "password-reset-flow",
  "csrf-token-bypass",
  "sqli",
  "xss",
  "ssrf",
];

const STATUSES = ["untested", "tested", "lead", "finding", "n/a", "blocked"];
const RESOLVED = new Set(["tested", "lead", "finding", "n/a", "blocked"]);
const NEEDS_REASON = new Set(["n/a", "blocked"]);

/**
 * Classes whose entire failure mode IS one identity reaching another's data. A
 * single-account test cannot falsify them, so allowing `tested` would manufacture
 * false confidence -- which is exactly what happened on the Threema hunt, where the
 * highest-payout class was untestable for want of a second account and that fact was
 * never recorded anywhere. These require `identities >= 2` or an explicit blocked reason.
 */
export const REQUIRES_TWO_IDENTITIES = ["idor", "account-takeover", "business-logic", "oauth"];

function sanitize(domain) {
  if (!domain || typeof domain !== "string") throw new Error("domain is required");
  const clean = domain
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .replace(/:\d+$/, "")
    .toLowerCase();
  if (!/^[a-z0-9.-]+$/.test(clean)) throw new Error(`invalid domain: ${domain}`);
  return clean;
}

export function apply(ctx, config = {}) {
  const cfg = { huntsRoot: join(REPO, "hunts"), skillsRoot: join(REPO, "skills"), ...config };

  const matrixPath = (domain) => join(cfg.huntsRoot, sanitize(domain), "coverage.json");

  async function readMatrix(domain) {
    try {
      return JSON.parse(await readFile(matrixPath(domain), "utf8"));
    } catch (err) {
      if (err.code === "ENOENT") return null;
      throw err;
    }
  }

  async function writeMatrix(domain, matrix) {
    const p = matrixPath(domain);
    await mkdir(dirname(p), { recursive: true });
    await writeFile(p, JSON.stringify(matrix, null, 2));
    return p;
  }

  async function discoverClasses() {
    const found = [];
    for (const sub of ["seeds", "learned"]) {
      try {
        const entries = await readdir(join(cfg.skillsRoot, sub));
        for (const e of entries) {
          if (!e.endsWith(".md")) continue;
          found.push(e.replace(/\.md$/, "").replace(/^h1-\d+-/, ""));
        }
      } catch {
        /* optional directory */
      }
    }
    return [...new Set(found)].sort();
  }

  async function discoverAssets(domain) {
    try {
      const raw = await readFile(join(cfg.huntsRoot, sanitize(domain), "scope.txt"), "utf8");
      return raw
        .split("\n")
        .map((l) => l.trim())
        // `!host` lines are EXCLUSIONS and `#` lines are comments: neither is a target.
        // Treating an excluded host as an asset made the gate demand testing hosts the
        // program explicitly forbids (caught by an end-to-end pipeline test).
        .filter((l) => l && !l.startsWith("#") && !l.startsWith("!"));
    } catch {
      return [];
    }
  }

  const cellId = (cls, asset) => `${cls}|${asset}`;

  ctx.tools.register({
    name: "coverage_init",
    description:
      "Build (or rebuild, preserving existing results) the vuln-class x asset coverage matrix for a hunt. Classes come from skills/seeds + skills/learned; assets come from scope.txt. Every cell starts `untested`.",
    parameters: {
      type: "object",
      properties: {
        domain: { type: "string" },
        classes: { type: "string", description: "Optional newline/comma-separated class list to override discovery." },
        assets: { type: "string", description: "Optional newline/comma-separated asset list to override scope.txt." },
      },
      required: ["domain"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const domain = sanitize(args.domain);
      const classes = args.classes
        ? String(args.classes).split(/[\n,]/).map((s) => s.trim()).filter(Boolean)
        : await discoverClasses();
      const assets = args.assets
        ? String(args.assets).split(/[\n,]/).map((s) => s.trim()).filter(Boolean)
        : await discoverAssets(domain);

      const existing = (await readMatrix(domain)) || { cells: {} };
      const cells = existing.cells || {};
      let created = 0;
      for (const c of classes) {
        for (const a of assets) {
          const id = cellId(c, a);
          if (!cells[id]) {
            cells[id] = { status: "untested", reason: "", evidence: [], ts: null };
            created += 1;
          }
        }
      }
      const matrix = { domain, classes, assets, cells, updated: new Date().toISOString() };
      const path = await writeMatrix(domain, matrix);
      return JSON.stringify({
        domain,
        path,
        classes: classes.length,
        assets: assets.length,
        cells_total: classes.length * assets.length,
        cells_created: created,
        cells_preserved: Object.keys(cells).length - created,
      });
    },
  });

  ctx.tools.register({
    name: "coverage_mark",
    description:
      "Record the outcome of testing one (vuln class, asset) pair. `n/a` and `blocked` REQUIRE a reason — this is how the hunt states honestly what it did not test instead of silently omitting it.",
    parameters: {
      type: "object",
      properties: {
        domain: { type: "string" },
        vulnClass: { type: "string" },
        asset: { type: "string" },
        status: { type: "string", enum: STATUSES },
        reason: { type: "string", description: "Required for n/a and blocked." },
        evidence: { type: "string", description: "Optional reference: request, journal summary, or file." },
        identities: {
          type: "number",
          description:
            "How many distinct accounts/identities were used. Cross-identity classes (IDOR, ATO, business-logic, OAuth) require >=2 to be marked tested.",
        },
      },
      required: ["domain", "vulnClass", "asset", "status"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const domain = sanitize(args.domain);
      const status = String(args.status || "").toLowerCase();
      if (!STATUSES.includes(status)) {
        return JSON.stringify({ marked: false, error: `unknown status: ${args.status}` });
      }
      if (NEEDS_REASON.has(status) && !String(args.reason || "").trim()) {
        return JSON.stringify({
          marked: false,
          error: `status "${status}" requires a reason (say what was not tested and why)`,
        });
      }
      const identities = Number.isFinite(args.identities) ? Number(args.identities) : 0;
      if (status === "tested" && REQUIRES_TWO_IDENTITIES.includes(args.vulnClass) && identities < 2) {
        return JSON.stringify({
          marked: false,
          error:
            `"${args.vulnClass}" cannot be marked tested with ${identities} identity/identities. ` +
            `One account cannot falsify a cross-identity bug. Pass identities>=2, or mark it ` +
            `blocked with a reason such as "no second account/tenant".`,
        });
      }
      let matrix = await readMatrix(domain);
      if (!matrix) {
        return JSON.stringify({ marked: false, error: "no coverage matrix — run coverage_init first" });
      }
      const id = cellId(args.vulnClass, args.asset);
      const prev = matrix.cells[id] || { evidence: [] };
      matrix.cells[id] = {
        status,
        reason: args.reason || "",
        evidence: args.evidence ? [...(prev.evidence || []), args.evidence] : prev.evidence || [],
        identities,
        ts: new Date().toISOString(),
      };
      if (!matrix.classes.includes(args.vulnClass)) matrix.classes.push(args.vulnClass);
      if (!matrix.assets.includes(args.asset)) matrix.assets.push(args.asset);
      await writeMatrix(domain, matrix);
      return JSON.stringify({ marked: true, cell: id, status, reason: args.reason || "" });
    },
  });

  ctx.tools.register({
    name: "coverage_gaps",
    description:
      "List untested coverage cells, grouped by asset. `criticalOnly` restricts to the classes that must be resolved before a hunt can claim completeness.",
    parameters: {
      type: "object",
      properties: {
        domain: { type: "string" },
        criticalOnly: { type: "boolean" },
        limit: { type: "number" },
      },
      required: ["domain"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const matrix = await readMatrix(args.domain);
      if (!matrix) return JSON.stringify({ error: "no coverage matrix", gaps: [] });
      const relevant = args.criticalOnly
        ? matrix.classes.filter((c) => CRITICAL_CLASSES.includes(c))
        : matrix.classes;
      const byAsset = {};
      let total = 0;
      for (const a of matrix.assets) {
        for (const c of relevant) {
          const cell = matrix.cells[cellId(c, a)];
          if (!cell || !RESOLVED.has(cell.status)) {
            (byAsset[a] ||= []).push(c);
            total += 1;
          }
        }
      }
      const limit = Number.isFinite(args.limit) ? args.limit : 500;
      return JSON.stringify({
        domain: matrix.domain,
        critical_only: !!args.criticalOnly,
        gaps_total: total,
        by_asset: byAsset,
        classes_considered: relevant.length,
        assets_considered: matrix.assets.length,
        truncated: total > limit,
      });
    },
  });

  ctx.tools.register({
    name: "coverage_summary",
    description: "Per-status counts and completion percentage for a hunt's coverage matrix.",
    parameters: {
      type: "object",
      properties: { domain: { type: "string" } },
      required: ["domain"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const matrix = await readMatrix(args.domain);
      if (!matrix) return JSON.stringify({ error: "no coverage matrix" });
      const byStatus = {};
      for (const cell of Object.values(matrix.cells)) {
        byStatus[cell.status] = (byStatus[cell.status] || 0) + 1;
      }
      const total = Object.keys(matrix.cells).length || 1;
      const resolved = Object.values(matrix.cells).filter((c) => RESOLVED.has(c.status)).length;
      const critTotal = matrix.assets.length * matrix.classes.filter((c) => CRITICAL_CLASSES.includes(c)).length || 1;
      const critResolved = matrix.assets.reduce(
        (n, a) =>
          n +
          matrix.classes.filter(
            (c) => CRITICAL_CLASSES.includes(c) && RESOLVED.has((matrix.cells[cellId(c, a)] || {}).status)
          ).length,
        0
      );
      return JSON.stringify({
        domain: matrix.domain,
        cells_total: Object.keys(matrix.cells).length,
        by_status: byStatus,
        completion_pct: Math.round((resolved / total) * 100),
        critical_completion_pct: Math.round((critResolved / critTotal) * 100),
        blocked: Object.entries(matrix.cells)
          .filter(([, v]) => v.status === "blocked")
          .map(([k, v]) => ({ cell: k, reason: v.reason })),
      });
    },
  });

  ctx.tools.register({
    name: "coverage_gate",
    description:
      "Enforcement point: PASS only when every critical (vuln class, asset) cell is resolved. Returns the blocking cells otherwise. Call before delivering a 'no findings' conclusion — an untested cell is not a clean bill of health.",
    parameters: {
      type: "object",
      properties: {
        domain: { type: "string" },
        threshold: { type: "number", description: "Minimum critical completion percentage (default 100)." },
      },
      required: ["domain"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const matrix = await readMatrix(args.domain);
      if (!matrix) {
        return JSON.stringify({
          pass: false,
          reason: "no coverage matrix — the hunt cannot demonstrate what it tested",
        });
      }
      const threshold = Number.isFinite(args.threshold) ? args.threshold : 100;
      const critClasses = matrix.classes.filter((c) => CRITICAL_CLASSES.includes(c));
      const blocking = [];
      for (const a of matrix.assets) {
        for (const c of critClasses) {
          const cell = matrix.cells[cellId(c, a)];
          if (!cell || !RESOLVED.has(cell.status)) {
            blocking.push({ asset: a, vuln_class: c, status: cell ? cell.status : "untested" });
          }
        }
      }
      const total = matrix.assets.length * critClasses.length || 1;
      const pct = Math.round(((total - blocking.length) / total) * 100);
      return JSON.stringify({
        pass: pct >= threshold,
        critical_completion_pct: pct,
        threshold,
        blocking_count: blocking.length,
        blocking: blocking.slice(0, 200),
        note:
          pct >= threshold
            ? "All critical cells resolved. A 'no findings' conclusion is now defensible."
            : "Unresolved critical cells remain. Do NOT report a clean result; resolve or explicitly mark each one n/a/blocked with a reason.",
      });
    },
  });

  console.log("[coverage] registered: init, mark, gaps, summary, gate (root =", cfg.huntsRoot, ")");
}
