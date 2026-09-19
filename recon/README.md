# Recon Workflow

10 phases. Each spawns a `recon` subagent.

## Output layout

All hunt-specific output goes under `~/.dsh/hunts/<domain>/`:

    ~/.dsh/hunts/<domain>/
      recon/01-subdomain-enum/
        scope.txt
        raw-subfinder.txt
        summary.json
      recon/02-dns-resolution/
        ...
      findings/
      chains/
      reports/
      events.jsonl

The parent agent receives only the JSON `summary.json` from each phase.
Raw output never enters the parent context.

## Invocation

The parent calls the `run_recon_phase` tool with:
    { phase: "01", domain: "example.com", scope: "<optional in-scope list>" }

The tool creates the phase directory, optionally writes `scope.txt`, and
spawns the subagent.
