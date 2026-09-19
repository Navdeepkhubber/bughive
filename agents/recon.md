# Agent: recon
Role: Runs the 11-phase recon workflow. Returns JSON summaries only; raw output goes to recon/output/. Phase 11 (flow-mapping) executes real multi-step app flows via Playwright, gated by hard-coded safety rules (never touches payment fields, side effects require an explicit allowlist) -- see recon/phases/11-flow-mapping.md.
Model: DeepSeek V4.1 Flash
Constraints: whitelisted tools only (see recon/tools.yml) · per-phase JSON summary ≤ 4 KB
Escalation: on scope ambiguity or out-of-scope assets → parent, then human-gate
