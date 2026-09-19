import { mkdir, writeFile, readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";

export const name = "chain-builder";
export const inject = ["tools", "sessions"];

function sanitizeDomain(d) {
  if (!d || typeof d !== "string") throw new Error("domain is required");
  const clean = d.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "").toLowerCase();
  if (!/^[a-z0-9.-]+$/.test(clean)) throw new Error(`invalid domain: ${d}`);
  return clean;
}

export function apply(ctx, config = {}) {
  const cfg = { playbooksDir: "./playbooks", huntsRoot: join(homedir(), ".dsh", "hunts"), ...config };

  ctx.tools.register({
    name: "build_chain",
    description: "Given validated findings, propose an A→B→C chain. Writes to ~/.dsh/hunts/<domain>/chains/.",
    parameters: {
      type: "object",
      properties: {
        domain:   { type: "string", description: "Target domain." },
        findings: { type: "string", description: "Validated findings as JSON array." },
      },
      required: ["domain", "findings"],
    },
    output: {
      schema: { type: "string" },
      render: (_args, value) => [{ type: "text", text: value }],
    },
    async execute(args) {
      const domain = sanitizeDomain(args.domain);
      const findings = JSON.parse(args.findings);

      let books = [];
      try { books = (await readdir(cfg.playbooksDir)).filter((f) => f.endsWith(".md")); } catch {}
      const bodies = await Promise.all(books.map((f) => readFile(join(cfg.playbooksDir, f), "utf-8")));

      const s = await ctx.sessions.create({ title: `chain-build ${domain}` });
      const r = await s.run(
        `Findings: ${JSON.stringify(findings)}\n\nPlaybooks:\n${bodies.join("\n---\n")}\n\n` +
        `Propose the strongest valid chain. Cite playbook. If none, say so.`,
        { maxTokens: 20000 }
      );
      const text = r.output || "";

      const dir = join(cfg.huntsRoot, domain, "chains");
      await mkdir(dir, { recursive: true });
      const path = join(dir, `chain-${Date.now()}.md`);
      await writeFile(path, text, "utf-8");

      return JSON.stringify({ path, length: text.length });
    },
  });

  console.log("[chain-builder] registered; writes to", cfg.huntsRoot, "<domain>/chains/");
}
