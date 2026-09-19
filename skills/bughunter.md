# SKILL: bughunter (master)
Hunt for real, exploitable bugs. Quality > quantity.

1. Read scope. Reject out-of-scope assets.
2. Load at most 3 vuln-class skills matching the target.
3. Delegate recon to `recon` subagent (10 phases).
4. Feed recon output to `hypothesis`.
5. Validate each hypothesis with `validator` (deterministic).
6. Run `chain-builder` on every validated finding.
7. Write report via `report-writer`.
8. High/Critical → `human-gate`. Always.

Never: submit unvalidated findings, test out of scope, exceed budget,
auto-escalate without approval.
