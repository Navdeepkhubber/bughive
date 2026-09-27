#!/usr/bin/env bash
# Phase 11 — flow mapping (multi-step flows, via headless Chromium).
#
# This phase previously degraded SILENTLY when Playwright was missing: it wrote a
# `tools_skipped` note and exited 0, so a whole hypothesis source (multi-step flows that
# the HTTP crawler can never see) was empty and nothing in the pipeline said so. That is
# a false negative produced by the harness itself, which is worse than a failed phase.
#
# It now distinguishes three states and makes each loud:
#   ready    -- chromium launches; the real flow runner executes.
#   degraded -- module present but the browser is not installed: runs katana AND marks
#               the phase `degraded: true` with an actionable remediation.
#   blocked  -- no runner at all: writes `degraded: true` and warns on stderr.
set -euo pipefail
source "$(dirname "$0")/_common.sh"

domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/11-flow-mapping"
mkdir -p "$out"

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
runner="$repo_root/recon/scripts/flow-runner.mjs"
playwright_pkg="$repo_root/node_modules/playwright/package.json"

if [ ! -f "$hd/scope.txt" ]; then
  echo '{"phase":"11-flow-mapping","count":0,"degraded":true,"notes":["scope.txt missing -- refusing to run (fail closed)"],"output_files":[]}' > "$out/summary.json"
  mark_done "$domain" "recon-11"
  echo '{"phase":"11","count":0,"degraded":true}'
  exit 0
fi

# Is chromium actually usable, not merely declared in node_modules?
browser_ready=0
if command -v node >/dev/null 2>&1 && [ -f "$playwright_pkg" ]; then
  if ( cd "$repo_root" && node -e "
      import('playwright').then(async (p) => {
        try { const b = await p.chromium.launch({ headless: true }); await b.close(); process.exit(0); }
        catch { process.exit(3); }
      }).catch(() => process.exit(3));
    " >/dev/null 2>&1 ); then
    browser_ready=1
  fi
fi

if [ "$browser_ready" -eq 1 ]; then
  log "flow-runner (playwright, chromium verified) for $domain"
  timeout 400 node "$runner" --domain "$domain" --hunts-root "$hd/.." >/dev/null 2>&1 || \
    log "flow-runner exited non-zero or timed out; check $out/summary.json for partial results"
  # The runner writes its own summary; make sure the contract fields are present.
  python3 - "$out/summary.json" "$domain" <<'PY'
import json, sys, os
path, domain = sys.argv[1], sys.argv[2]
try:
    s = json.load(open(path))
except Exception:
    s = {}
s.setdefault("phase", "11-flow-mapping")
s["domain"] = domain
s["degraded"] = False
s.setdefault("count", 0)
json.dump(s, open(path, "w"), indent=2)
PY
  mark_done "$domain" "recon-11"
  count=$(python3 -c "
import json
try: print(json.load(open('$out/summary.json')).get('count',0))
except Exception: print(0)")
  echo '{"phase":"11","count":'"$count"',"degraded":false}'
  exit 0
fi

# ---- degraded / blocked -------------------------------------------------------
reason="playwright module or chromium browser not installed"
log "WARNING: phase 11 DEGRADED — $reason"
log "         Multi-step flow mapping is NOT running; flows are an empty hypothesis source."
log "         Fix: (cd $repo_root && npm install && npx playwright install chromium)"
log "         Then: bash scripts/pipeline/run.sh recon-11 $domain"

if command -v katana >/dev/null 2>&1; then
  log "falling back to katana discovery-only pass for $domain"
  timeout 180 katana -u "https://$domain" -aff -jc -silent -o "$out/raw-katana.txt" 2>/dev/null || true
  count=$( [ -f "$out/raw-katana.txt" ] && wc -l < "$out/raw-katana.txt" || echo 0 )
  cat > "$out/summary.json" <<EOF
{"phase":"11-flow-mapping","domain":"$domain","degraded":true,"tools_run":["katana"],"tools_skipped":[{"tool":"playwright","reason":"$reason"}],"count":$count,"items":[],"notes":["DEGRADED: katana discovery-only found candidate flow entries but executed no multi-step flow. Flows are unverified and this phase must not be treated as complete. Fix: cd $repo_root && npm install && npx playwright install chromium && bash scripts/pipeline/run.sh recon-11 $domain"],"output_files":["$out/raw-katana.txt"]}
EOF
else
  cat > "$out/summary.json" <<EOF
{"phase":"11-flow-mapping","domain":"$domain","degraded":true,"count":0,"tools_run":[],"tools_skipped":[{"tool":"playwright","reason":"$reason"},{"tool":"katana","reason":"not installed"}],"items":[],"notes":["DEGRADED: no flow-mapping tool available. Multi-step flows were not tested at all; treat any 'no findings' claim over flows as unverified."],"output_files":[]}
EOF
fi

mark_done "$domain" "recon-11"
echo '{"phase":"11","degraded":true}'
