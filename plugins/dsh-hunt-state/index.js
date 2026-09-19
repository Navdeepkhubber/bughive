import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";

export const name = "hunt-state";
export const inject = ["tools"];

const STAGES = [
  "scope",
  "recon",
  "hypothesis",
  "skills",
  "fp_prefilter",
  "falsifier",
  "proof_validator",
  "chain",
  "report",
  "quality",
  "deliver",
];

function sanitize(d) {
  if (!d || typeof d !== "string") throw new Error("domain is required");
  const clean = d.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "").toLowerCase();
  if (!/^[a-z0-9.-]+$/.test(clean)) throw new Error(`invalid domain: ${d}`);
  return clean;
}

export function apply(ctx, config = {}) {
  const cfg = { huntsRoot: join(homedir(), ".dsh", "hunts"), ...config };

  const hd = (domain) => join(cfg.huntsRoot, sanitize(domain));

  ctx.tools.register({
    name: "hunt_init",
    description:
      "Create the hunt directory layout for a domain and write scope.txt. Idempotent — safe to call more than once.",
    parameters: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Target root domain." },
        scope:  { type: "string", description: "In-scope host list, one per line. If omitted, defaults to <domain>." },
      },
      required: ["domain"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const domain = sanitize(args.domain);
      const root = hd(domain);
      for (const sub of ["recon", "findings", "chains", "reports", "logs", ".state"]) {
        await mkdir(join(root, sub), { recursive: true });
      }
      const scopePath = join(root, "scope.txt");
      const scopeText = args.scope && args.scope.trim() ? args.scope.trim() : domain;
      await writeFile(scopePath, scopeText, "utf-8");
      return JSON.stringify({ domain, root, scope_path: scopePath, stages: STAGES });
    },
  });

  ctx.tools.register({
    name: "hunt_status",
    description: "Return which stages of a hunt are complete and which are next.",
    parameters: {
      type: "object",
      properties: { domain: { type: "string" } },
      required: ["domain"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const domain = sanitize(args.domain);
      const stateDir = join(hd(domain), ".state");
      let done = [];
      try { done = (await readdir(stateDir)).filter((f) => f.endsWith(".done")).map((f) => f.replace(".done", "")); }
      catch {}
      const next = STAGES.find((s) => !done.includes(s));
      return JSON.stringify({ domain, done, next, all: STAGES });
    },
  });

  ctx.tools.register({
    name: "hunt_mark",
    description: "Mark a stage as complete for a hunt. Call this after each stage finishes.",
    parameters: {
      type: "object",
      properties: {
        domain: { type: "string" },
        stage:  { type: "string", description: `One of: ${STAGES.join(", ")}` },
        note:   { type: "string", description: "Optional short note." },
      },
      required: ["domain", "stage"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const domain = sanitize(args.domain);
      if (!STAGES.includes(args.stage)) throw new Error(`unknown stage: ${args.stage}`);
      const path = join(hd(domain), ".state", `${args.stage}.done`);
      await mkdir(join(hd(domain), ".state"), { recursive: true });
      await writeFile(path, JSON.stringify({ ts: new Date().toISOString(), note: args.note || null }) + "\n", "utf-8");
      return JSON.stringify({ marked: args.stage, path });
    },
  });

  console.log("[hunt-state] registered — hunt_init / hunt_status / hunt_mark");
}
