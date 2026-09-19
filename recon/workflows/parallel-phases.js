// bughive: run recon phases in parallel where the dependency graph allows.
// Invoked via the `workflow` tool with { domain, phases }.

const { domain, phases, huntsRoot } = args;

if (!domain) throw new Error("domain is required");
if (!Array.isArray(phases) || phases.length === 0)
  throw new Error("phases array is required");

const phaseDir = (p) => `${huntsRoot}/${domain}/recon/${p}`;

log(`parallel-phases: ${phases.length} phases for ${domain}`);

const results = await parallel(
  phases.map((phase) => async () => {
    log(`  → phase ${phase}`);
    const reply = await agent({
      prompt:
        `You are the recon subagent for bughive.\n` +
        `Execute recon phase ${phase} on ${domain}.\n` +
        `Read recon/phases/${phase}.md for exact steps.\n` +
        `Write raw output to ${phaseDir(phase)}/.\n` +
        `Write summary.json to ${phaseDir(phase)}/summary.json.\n` +
        `Return ONLY the JSON summary. No prose.`,
      maxTokens: 30000,
    });
    return { phase, reply };
  })
);

log(`parallel-phases: all ${results.length} phases done`);
return JSON.stringify(results);
