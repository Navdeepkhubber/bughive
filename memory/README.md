# Cross-session memory
- facts.db (SQLite): targets, scopes, credentials, findings, chains
- Schema:
  targets(program, scope, tech_stack, last_recon_at)
  credentials(program, label, username, secret_blob)
  findings(program, endpoint, vuln_class, severity, status)
  chains(program, from_finding, to_finding, narrative)
- Access via ctx.memory. Never load raw memory into parent context.
