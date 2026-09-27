#!/usr/bin/env bash
# Phase 07 — JS/HTML security analysis.
#
# Previously a stub (count always 0), which meant the pipeline collected JS bundles and
# never looked inside them. This now:
#   1. collects JS/HTML asset URLs discovered by earlier phases,
#   2. downloads a BOUNDED, rate-limited sample into assets/ (skipped if already present),
#   3. runs the shared dsh-js-analyzer rule engine over everything on disk.
#
# Leads (client-side redirect allowlists, client-side authz, DOM XSS sinks, postMessage
# handlers, secrets, debug flags, internal hosts, graphql, jwt handling) land in
# items.jsonl with a suggested next request. Endpoints land in endpoints.txt.
#
# Network use is bounded and non-destructive: GET only, hard file cap, per-request timeout.
set -euo pipefail
source "$(dirname "$0")/_common.sh"
domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/07-js-analysis"
assets="$out/assets"
mkdir -p "$out" "$assets"

MAX_ASSETS="${BH_JS_MAX_ASSETS:-60}"

# ---------------------------------------------------------------- asset URLs
urls="$out/asset_urls.txt"
: > "$urls"
for f in "$hd/recon/all_endpoints" \
         "$hd/recon/04-http-probe/urls.txt" \
         "$hd/recon/04-http-probe/httpx.txt" \
         "$hd/recon/05-content-discovery/items.jsonl" \
         "$hd/recon/17-interesting-endpoints/items.jsonl"; do
  [ -f "$f" ] || continue
  grep -oiE 'https?://[^"'"'"' <>]+\.(js|mjs|html?)(\?[^"'"'"' <>]*)?' "$f" >> "$urls" 2>/dev/null || true
done
sort -u "$urls" -o "$urls" 2>/dev/null || true

# ---------------------------------------------------------------- download (bounded)
downloaded=0
if [ ! -d "$assets" ] || [ -z "$(ls -A "$assets" 2>/dev/null || true)" ]; then
  while IFS= read -r u; do
    [ -n "$u" ] || continue
    [ "$downloaded" -ge "$MAX_ASSETS" ] && break
    name="$(printf '%s' "$u" | (md5 -q 2>/dev/null || md5sum | cut -d' ' -f1))"
    curl -sS --max-time 15 -A "bh-recon/0.1 (authorized; non-destructive)" \
         -o "$assets/$name" "$u" >/dev/null 2>&1 || true
    downloaded=$((downloaded + 1))
    sleep 0.3   # stay polite: never turn recon into a flood
  done < "$urls"
fi

# ---------------------------------------------------------------- analyse
scan_count=$(find "$assets" -type f 2>/dev/null | wc -l | tr -d ' ')
if [ "$scan_count" -eq 0 ]; then
  # Nothing fetched: still scan any assets other phases left behind in recon/.
  node "$WS_ROOT/plugins/dsh-js-analyzer/cli.mjs" "$hd/recon" --out "$out" >/dev/null
else
  node "$WS_ROOT/plugins/dsh-js-analyzer/cli.mjs" "$assets" --out "$out" >/dev/null
fi

# ---------------------------------------------------------------- phase contract
count=$(python3 -c "
import json
try:
    print(json.load(open('$out/summary.json')).get('count', 0))
except Exception:
    print(0)
")
python3 - "$out/summary.json" "$domain" "$scan_count" "$downloaded" <<'PY'
import json, sys
path, domain, scanned, downloaded = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
try:
    s = json.load(open(path))
except Exception:
    s = {}
s["domain"] = domain
s["assets_downloaded"] = downloaded
s["assets_on_disk"] = scanned
json.dump(s, open(path, "w"), indent=2)
PY

mark_done "$domain" "recon-07"
echo '{"phase":"07","count":'"$count"'}'
