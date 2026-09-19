export const name = "report-writer";
export const inject = ["tools", "subagents"];

// See plugins/dsh-recon-orchestrator/index.js for the full rationale.
async function runChild(ctx, cfg, label, promptText, exec) {
  const subagents = ctx.get("subagents");
  if (!subagents) {
    throw new Error("write_report requires the `subagents` service (ctx.subagents/ctx.get('subagents'))");
  }
  if (!exec || !exec.agent) {
    throw new Error("write_report requires a calling agent (exec.agent)");
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
  const cfg = { template: "hackerone", provider: "spawn", maxTokens: 60000, reasoningEffort: "medium", ...config };

  ctx.tools.register({
    name: "write_report",
    description: "Produce a HackerOne-format report markdown for a validated finding (and optional chain). Never submits, only drafts.",
    parameters: {
      type: "object",
      properties: {
        finding: { type: "string", description: "Validated finding as JSON." },
        chain: { type: "string", description: "Optional chain as JSON." },
      },
      required: ["finding"],
    },
    output: {
      schema: { type: "string" },
      render: (_args, value) => [{ type: "text", text: value }],
    },
    async execute(args, exec) {
      // Intentionally uncaught: malformed input is a caller bug, not a
      // network condition -- the registry surfaces it as an isError result.
      const finding = JSON.parse(args.finding);
      const chain = args.chain ? JSON.parse(args.chain) : null;

      const prompt =
        `Write a HackerOne report. Sections: Title, Severity, Summary, Steps to Reproduce, Impact, Remediation, Evidence.\n` +
        `Finding: ${JSON.stringify(finding)}\nChain: ${JSON.stringify(chain)}\n` +
        `Do NOT fabricate. Mark [NEEDS EVIDENCE] for missing artifacts.`;

      return runChild(ctx, cfg, `report ${finding.id || "?"}`, prompt, exec);
    },
  });

  console.log("[report-writer] registered; template =", cfg.template);
}
