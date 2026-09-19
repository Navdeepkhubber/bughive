#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"
domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/14-nuclei-scan"
mkdir -p "$out"

webapps="$hd/recon/webapps"
if [ ! -f "$webapps" ]; then
  for f in "$hd"/recon/04-http-probe/summary.json; do
    [ -f "$f" ] && python3 -c "
import json
d=json.load(open('$f'))
for host,rows in d.get('results',{}).items():
    for r in (rows if isinstance(rows,list) else [rows]):
        u=r.get('url') if isinstance(r,dict) else None
        if u: print(u)
" > "$webapps" 2>/dev/null || true
  done
fi
[ -f "$webapps" ] || : > "$webapps"

if command -v nuclei >/dev/null 2>&1; then
  log "nuclei scanning $domain webapps"
  timeout 1200 nuclei -l "$webapps" -severity critical,high,medium,low -jsonl -o "$out/nuclei_output.jsonl" -silent 2>/dev/null || true
  count=0
  items="[]"
  if [ -f "$out/nuclei_output.jsonl" ]; then
    count=$(wc -l < "$out/nuclei_output.jsonl" | tr -d ' ')
    items=$(python3 -c "
import json
rows=[]
try:
    for line in open('$out/nuclei_output.jsonl'):
        line=line.strip()
        if not line: continue
        d=json.loads(line)
        rows.append({
            'template': d.get('template-id',''),
            'severity': d.get('info',{}).get('severity',''),
            'host': d.get('host',''),
            'matched_at': d.get('matched-at',''),
            'description': d.get('info',{}).get('name',''),
        })
except Exception:
    pass
print(json.dumps(rows))
" 2>/dev/null || echo "[]")
  fi
  cat > "$out/summary.json" <<EOF
{"phase":"14-nuclei-scan","domain":"$domain","tools_run":["nuclei"],"tools_skipped":[],"count":$count,"items":$items,"notes":[],"output_files":["$out/nuclei_output.jsonl"]}
EOF
else
  echo '{"phase":"14-nuclei-scan","domain":"'"$domain"'","tools_run":[],"tools_skipped":[{"tool":"nuclei","reason":"not installed -- no reasonable manual substitute for a signature database this size"}],"count":0,"items":[],"notes":[],"output_files":[]}' > "$out/summary.json"
fi

mark_done "$domain" "recon-14"
echo '{"phase":"14"}'
