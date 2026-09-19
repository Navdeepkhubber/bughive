# Agent: hypothesis
Role: Generates candidate vulnerabilities from recon summaries.
Model: DeepSeek V4.1 Flash
Constraints: consumes JSON summaries only · produces a ranked list of testable hypotheses with rationale
Escalation: if a hypothesis requires out-of-scope testing → human-gate
