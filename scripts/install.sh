#!/usr/bin/env bash
set -euo pipefail
PROFILE="${DSH_PROFILE:-web}"
echo "→ Installing into DSH profile: $PROFILE"
dsh plugin --profile "$PROFILE" add "github:PerryLink/dsh-budget#main"      || true
dsh plugin --profile "$PROFILE" add "github:dmsobtl/dsh-skill-evolve#main" || true
for p in plugins/*/; do
  [ -f "$p/package.json" ] || continue
  echo "  + $p"
  ( cd "$p" && dsh plugin --profile "$PROFILE" add . )
done
echo "→ Verifying config"
dsh --profile "$PROFILE" --dump-config | grep -E 'id: (h1-classifier|bounty-budget|critical-gate|recon-orchestrator|skill-loader|finding-validator|chain-builder|report-writer|observability|fp-filter|hunt-state|report-quality|skill-admission)' \
  || { echo "!! Some plugins failed to register"; exit 1; }
echo "✓ Restart DSH: dsh --profile $PROFILE"
