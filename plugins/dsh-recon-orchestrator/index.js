import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";

export const name = "recon-orchestrator";
export const inject = ["tools", "subagents"];

function sanitizeDomain(d) {
  if (!d || typeof d !== "string") throw new Error("domain is required");
  const clean = d.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "").toLowerCase();
  if (!/^[a-z0-9.-]+$/.test(clean)) throw new Error(`invalid domain: ${d}`);
  return clean;
}

// Shared by every agent-backed plugin in this repo. `ctx.sessions.create().run()`
// does not exist on the installed DSH API (Session has no `.run`); the
// sanctioned way to spawn a child agent and await its text is
// `ctx.subagents.start()`. See plugins/PLUGIN-FIXES.md for the full API
// citation trail this is ported from.
async function runChild(ctx, cfg, label, promptText, exec) {
  const subagents = ctx.get("subagents");
  if (!subagents) {
    throw new Error("run_recon_phase requires the `subagents` service (ctx.subagents/ctx.get('subagents'))");
  }
  if (!exec || !exec.agent) {
    throw new Error("run_recon_phase requires a calling agent (exec.agent)");
  }
  const providers = subagents.list ? subagents.list() : [];
  if (!subagents.getProvider(cfg.provider)) {
    throw new Error(`provider "${cfg.provider}" is not registered; available: ${providers.join(", ")}`);
  }

  const run = await subagents.start(cfg.provider, {
    label,
    prompt: [{ type: "text", text: promptText }],
    parent: exec.agent,
    signal: exec.signal,
    agentOptions: { maxTokens: cfg.maxTokens, ...(cfg.reasoningEffort ? { reasoningEffort: cfg.reasoningEffort } : {}) },
  });

  try {
    const result = await run.result;
    if (result.stopReason !== "completed") {
      throw new Error(
        `child ended abnormally (${result.stopReason})${result.diagnostic ? `: ${result.diagnostic}` : ""}`
      );
    }
    return (result.output || []).filter((b) => b.type === "text").map((b) => b.text).join("");
  } finally {
    await run.dispose();
  }
}

export function apply(ctx, config = {}) {
  const cfg = {
    phasesDir: "./recon/phases",
    outputDir: "./recon/output",
    huntsRoot: join(homedir(), ".dsh", "hunts"),
    provider: "spawn",
    maxTokens: 30000,
    // Recon phases follow a fixed, documented procedure per recon/phases/*.md
    // (run these tools, parse this output, write this JSON shape) -- there's
    // little open-ended reasoning involved, so this doesn't need the same
    // reasoning budget as hypothesis/chain/report generation. Override with
    // config if a specific deployment's phases need more.
    reasoningEffort: "low",
    ...config,
  };

  ctx.tools.register({
    name: "run_recon_phase",
    description: "Run one numbered recon phase against a target domain. Writes raw output to ~/.dsh/hunts/<domain>/recon/<phase>/. Returns a JSON summary.",
    parameters: {
      type: "object",
      properties: {
        phase: { type: "string", description: "Phase number, e.g. 01." },
        domain: { type: "string", description: "Target root domain (e.g. bdo.ch)." },
        scope: { type: "string", description: "Optional: in-scope host list, one per line. Written to scope.txt." },
      },
      required: ["phase", "domain"],
    },
    output: {
      schema: { type: "string" },
      render: (_args, value) => [{ type: "text", text: value }],
    },
    async execute(args, exec) {
      const domain = sanitizeDomain(args.domain);
      const phaseDir = join(cfg.huntsRoot, domain, "recon", args.phase);
      await mkdir(phaseDir, { recursive: true });

      if (args.scope) {
        await writeFile(join(phaseDir, "scope.txt"), args.scope, "utf-8");
      }

      const scopeLine = args.scope ? `\nScope written to ${phaseDir}/scope.txt. Read it before running tools.` : "";

      const prompt =
        `Execute recon phase ${args.phase} on ${domain}. ` +
        `Read ${cfg.phasesDir}/${args.phase}.md for exact steps. ` +
        `Write raw output to ${phaseDir}/ (this directory exists). ` +
        `Emit a JSON summary and write it to ${phaseDir}/summary.json. ` +
        `Return ONLY the JSON summary.${scopeLine}`;

      return runChild(ctx, cfg, `recon ${args.phase} ${domain}`, prompt, exec);
    },
  });

  console.log("[recon-orchestrator] registered; huntsRoot =", cfg.huntsRoot);
}
