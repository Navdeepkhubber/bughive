import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

export const name = "chain-builder";
export const inject = ["tools", "subagents"];

// See plugins/dsh-recon-orchestrator/index.js for the full rationale: this
// is the sanctioned ctx.subagents.start() pattern, replacing the
// nonexistent ctx.sessions.create().run().
async function runChild(ctx, cfg, label, promptText, exec) {
  const subagents = ctx.get("subagents");
  if (!subagents) {
    throw new Error("build_chain requires the `subagents` service (ctx.subagents/ctx.get('subagents'))");
  }
  if (!exec || !exec.agent) {
    throw new Error("build_chain requires a calling agent (exec.agent)");
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
  const cfg = { playbooksDir: "./playbooks", provider: "spawn", maxTokens: 20000, reasoningEffort: "high", ...config };

  ctx.tools.register({
    name: "build_chain",
    description: "Given validated findings, propose an A->B->C exploit chain citing the matching playbook.",
    parameters: {
      type: "object",
      properties: {
        findings: { type: "string", description: "Validated findings as a JSON array." },
      },
      required: ["findings"],
    },
    output: {
      schema: { type: "string" },
      render: (_args, value) => [{ type: "text", text: value }],
    },
    async execute(args, exec) {
      // Intentionally uncaught: malformed input is a caller bug, not a
      // network condition -- the registry surfaces it as an isError result.
      const findings = JSON.parse(args.findings);

      let books = [];
      try { books = (await readdir(cfg.playbooksDir)).filter((f) => f.endsWith(".md")); } catch { /* no playbooks dir yet */ }
      const bodies = await Promise.all(books.map((f) => readFile(join(cfg.playbooksDir, f), "utf-8")));

      const prompt =
        `Build an exploit chain from these validated findings, citing the matching playbook if one applies.\n\n` +
        `Findings: ${JSON.stringify(findings)}\n\n` +
        `Playbooks:\n${bodies.join("\n---\n")}\n\n` +
        `Propose the strongest valid chain. Cite the playbook. If none applies, say so.`;

      return runChild(ctx, cfg, "chain-build", prompt, exec);
    },
  });

  console.log("[chain-builder] registered; playbooksDir =", cfg.playbooksDir);
}
