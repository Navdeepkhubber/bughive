#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"
domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/17-interesting-endpoints"
endpoints="$hd/recon/all_endpoints"
cache="$hd/recon/12-response-cache"
mkdir -p "$out"

KEYWORDS='admin|api/|graphql|debug|swagger|internal|openapi|actuator'

items_file="$out/items.jsonl"
: > "$items_file"

if [ -f "$endpoints" ]; then
  grep -iE "$KEYWORDS" "$endpoints" 2>/dev/null | while read -r url; do
    kw=$(echo "$url" | grep -ioE "$KEYWORDS" | head -1)
    python3 -c "import json,sys; print(json.dumps({'url':sys.argv[1],'matched_keyword':sys.argv[2]}))" "$url" "$kw" >> "$items_file"
  done || true
fi

if [ -d "$cache" ]; then
  grep -rliE "$KEYWORDS" "$cache" 2>/dev/null | while read -r f; do
    kw=$(grep -ioE "$KEYWORDS" "$f" 2>/dev/null | head -1)
    python3 -c "import json,sys; print(json.dumps({'url':sys.argv[1],'matched_keyword':sys.argv[2],'source':'response-body'}))" "$f" "$kw" >> "$items_file"
  done || true
fi

count=$(grep -c . "$items_file" 2>/dev/null || true)
items_json=$(python3 -c "
import json
rows=[]
try:
    for line in open('$items_file'):
        line=line.strip()
        if line: rows.append(json.loads(line))
except Exception:
    pass
print(json.dumps(rows))
")

cat > "$out/summary.json" <<EOF
{"phase":"17-interesting-endpoints","domain":"$domain","tools_run":["grep"],"tools_skipped":[],"count":$count,"items":$items_json,"notes":[],"output_files":["$items_file"]}
EOF

mark_done "$domain" "recon-17"
echo '{"phase":"17","count":'"$count"'}'
