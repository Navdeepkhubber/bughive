#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"
domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/12-response-cache"
mkdir -p "$out"

# Build all_endpoints from phases 04/05/06 if not already present.
endpoints_file="$hd/recon/all_endpoints"
if [ ! -f "$endpoints_file" ]; then
  : > "$endpoints_file"
  for f in "$hd"/recon/0{4,5,6}-*/summary.json; do
    [ -f "$f" ] || continue
    python3 -c "
import json,sys
try:
    d=json.load(open('$f'))
except Exception:
    sys.exit(0)
def walk(x):
    if isinstance(x,str) and x.startswith('http'):
        print(x.split()[0])
    elif isinstance(x,dict):
        for v in x.values(): walk(v)
    elif isinstance(x,list):
        for v in x: walk(v)
walk(d.get('items', d.get('results', [])))
" >> "$endpoints_file" 2>/dev/null || true
  done
  sort -u -o "$endpoints_file" "$endpoints_file"
fi

count=0
if command -v fff >/dev/null 2>&1; then
  log "fff dumping responses for $domain"
  timeout 1200 bash -c "cat '$endpoints_file' | fff -S -k -o '$out'" 2>/dev/null || true
  count=$(find "$out" -name '*.body' 2>/dev/null | wc -l | tr -d ' ')
  cat > "$out/summary.json" <<EOF
{"phase":"12-response-cache","domain":"$domain","tools_run":["fff"],"tools_skipped":[],"count":$count,"items":[],"notes":["cache root: $out"],"output_files":["$out"]}
EOF
else
  log "fff not installed; curl fallback for response cache"
  while read -r url; do
    [ -z "$url" ] && continue
    safe=$(echo "$url" | sed 's#https\?://##; s#[/:?&=]#_#g' | cut -c1-200)
    timeout 15 curl -sS -D "$out/${safe}.headers" -o "$out/${safe}.body" "$url" 2>/dev/null || true
    count=$((count + 1))
  done < "$endpoints_file"
  cat > "$out/summary.json" <<EOF
{"phase":"12-response-cache","domain":"$domain","tools_run":["curl"],"tools_skipped":[{"tool":"fff","reason":"not installed"}],"count":$count,"items":[],"notes":["cache root: $out"],"output_files":["$out"]}
EOF
fi

mark_done "$domain" "recon-12"
echo '{"phase":"12","cached":'"$count"'}'
