#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"

domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/11-flow-mapping"
mkdir -p "$out"

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
runner="$repo_root/recon/scripts/flow-runner.mjs"

if [ ! -f "$hd/scope.txt" ]; then
  echo '{"phase":"11-flow-mapping","count":0,"notes":["scope.txt missing -- refusing to run (fail closed)"],"output_files":[]}' > "$out/summary.json"
  mark_done "$domain" "recon-11"
  echo '{"phase":"11","count":0}'
  exit 0
fi

if command -v node >/dev/null 2>&1 && [ -f "$repo_root/node_modules/playwright/package.json" ]; then
  log "flow-runner (playwright) for $domain"
  timeout 400 node "$runner" --domain "$domain" --hunts-root "$hd/.." >/dev/null 2>&1 || \
    log "flow-runner exited non-zero or timed out; check $out/summary.json for partial results"
elif command -v katana >/dev/null 2>&1; then
  log "playwright unavailable; falling back to katana discovery-only pass for $domain"
  timeout 180 katana -u "https://$domain" -aff -jc -silent -o "$out/raw-katana.txt" 2>/dev/null || true
  count=$( [ -f "$out/raw-katana.txt" ] && wc -l < "$out/raw-katana.txt" || echo 0 )
  cat > "$out/summary.json" <<EOF
{"phase":"11-flow-mapping","domain":"$domain","tools_run":["katana"],"tools_skipped":[{"tool":"playwright","reason":"not installed"}],"count":$count,"items":[],"notes":["katana discovery-only: found candidate flow-entry URLs but did not execute any multi-step flow. Run: npm install && npx playwright install chromium, then re-run this phase for real flow execution."],"output_files":["$out/raw-katana.txt"]}
EOF
else
  echo '{"phase":"11-flow-mapping","count":0,"tools_skipped":[{"tool":"playwright","reason":"not installed"},{"tool":"katana","reason":"not installed"}],"notes":["no flow-mapping tool available"],"output_files":[]}' > "$out/summary.json"
fi

mark_done "$domain" "recon-11"
echo '{"phase":"11"}'
