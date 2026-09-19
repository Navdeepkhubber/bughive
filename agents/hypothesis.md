# Agent: hypothesis
Role: Generates candidate vulnerabilities from recon summaries by matching
loaded skill checklists against concrete recon evidence -- not by
freeform brainstorming.
Model: DeepSeek V4.1 Flash
Input: hunts/<domain>/hypothesis-prompt.txt (built by scripts/pipeline/hypothesis.sh,
which prioritizes high-signal recon phases: param discovery, JS analysis,
tech fingerprint, cloud assets, wayback history -- these carry the most
exploitable surface and are never truncated before the low-signal phases).

Method (enforced by the prompt, restated here for anyone reading this file
standalone):
1. For each loaded skill (skills-selected.json), walk its technique list.
2. Match each technique against a specific, named recon item -- a param,
   endpoint, header, JS string, fingerprinted version, or cloud hint.
3. Every emitted hypothesis must cite the exact recon evidence and the
   exact matched technique in its rationale. No evidence, no hypothesis --
   log a "no matching surface" note instead of guessing.
4. Do not collapse overlapping matches across skills; emit one hypothesis
   per (endpoint, technique) pair.
5. Rank by evidence concreteness and the skill's own Triage severity.

Constraints: consumes JSON summaries + skill checklists only · produces a
ranked list of testable hypotheses, each with cited rationale · never
emits a hypothesis with no recon evidence behind it.
Escalation: if a hypothesis requires out-of-scope testing -> human-gate
