import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";

export const name = "recon-orchestrator";
export const inject = ["tools", "sessions"];

function sanitizeDomain(d) {
  if (!d || typeof d !== "string") throw new Error("domain is required");
  const clean = d.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "").toLowerCase();
  if (!/^[a-z0-9.-]+$/.test(clean)) throw new Error(`invalid domain: ${d}`);
  return clean;
}

export function apply(ctx, config = {}) {
  const cfg = { phasesDir: "./recon/phases", huntsRoot: join(homedir(), ".dsh", "hunts"), ...config };

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
    async execute(args) {
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

      const s = await ctx.sessions.create({ title: `recon ${args.phase} ${domain}` });
      const r = await s.run(prompt, { maxTokens: 30000 });
      return r.output || "";
    },
  });

  console.log("[recon-orchestrator] registered; huntsRoot =", cfg.huntsRoot);
}
