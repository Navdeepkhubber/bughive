import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";

export const name = "report-writer";
export const inject = ["tools", "sessions"];

function sanitizeDomain(d) {
  if (!d || typeof d !== "string") throw new Error("domain is required");
  const clean = d.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "").toLowerCase();
  if (!/^[a-z0-9.-]+$/.test(clean)) throw new Error(`invalid domain: ${d}`);
  return clean;
}

export function apply(ctx, config = {}) {
  const cfg = { huntsRoot: join(homedir(), ".dsh", "hunts"), ...config };

  ctx.tools.register({
    name: "write_report",
    description: "Produce a HackerOne-format report and write it to ~/.dsh/hunts/<domain>/reports/.",
    parameters: {
      type: "object",
      properties: {
        domain:  { type: "string", description: "Target domain." },
        finding: { type: "string", description: "Validated finding as JSON." },
        chain:   { type: "string", description: "Optional chain as JSON." },
      },
      required: ["domain", "finding"],
    },
    output: {
      schema: { type: "string" },
      render: (_args, value) => [{ type: "text", text: value }],
    },
    async execute(args) {
      const domain = sanitizeDomain(args.domain);
      const finding = JSON.parse(args.finding);
      const chain = args.chain ? JSON.parse(args.chain) : null;

      const s = await ctx.sessions.create({ title: `report ${domain}` });
      const r = await s.run(
        `Write a HackerOne report. Sections: Title, Severity, Summary, Steps to Reproduce, Impact, Remediation, Evidence.\n` +
        `Finding: ${JSON.stringify(finding)}\nChain: ${JSON.stringify(chain)}\n` +
        `Do NOT fabricate. Mark [NEEDS EVIDENCE] for missing artifacts.`,
        { maxTokens: 60000 }
      );
      const text = r.output || "";

      const dir = join(cfg.huntsRoot, domain, "reports");
      await mkdir(dir, { recursive: true });
      const id = finding.id || Date.now();
      const path = join(dir, `report-${id}.md`);
      await writeFile(path, text, "utf-8");

      return JSON.stringify({ path, length: text.length });
    },
  });

  console.log("[report-writer] registered; writes to", cfg.huntsRoot, "<domain>/reports/");
}
