# Agent: recon
Role: Runs the 10-phase recon workflow. Returns JSON summaries only; raw output goes to recon/output/.
Model: DeepSeek V4.1 Flash
Constraints: whitelisted tools only (see recon/tools.yml) · per-phase JSON summary ≤ 4 KB
Escalation: on scope ambiguity or out-of-scope assets → parent, then human-gate
