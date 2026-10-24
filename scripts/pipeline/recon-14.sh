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
  script_dir="$(cd "$(dirname "$0")" && pwd)"
  eval "$(python3 "$script_dir/_batch.py" exports)"
  # Severity-first: critical/high consume the budget before medium/low.
  # NUCLEI_RATE_LIMIT still overrides the knob for programs that demand a lower rate.
  # The global -rl is the real throttle; -c and -bs do not outrun it.
  nuclei_rl="${NUCLEI_RATE_LIMIT:-${BUGHIVE_NUCLEI_RATE:-150}}"
  nuclei_c="${BUGHIVE_NUCLEI_CONCURRENCY:-25}"
  nuclei_bs="${BUGHIVE_NUCLEI_BULK:-25}"
  nuclei_budget="${BUGHIVE_NUCLEI_BUDGET_SECONDS:-1200}"
  nuclei_cap="${BUGHIVE_NUCLEI_RESULT_CAP:-500}"
  sev_first="${BUGHIVE_NUCLEI_SEVERITY_FIRST:-critical,high}"
  sev_rest="${BUGHIVE_NUCLEI_SEVERITY_REST:-medium,low}"
  if [ -n "${BUGHIVE_TRANCHE_HOSTS:-}" ] && [ -f "${BUGHIVE_TRANCHE_HOSTS}" ]; then
    python3 - "$webapps" "$BUGHIVE_TRANCHE_HOSTS" <<'PY'
import sys
from pathlib import Path
from urllib.parse import urlsplit
web, hosts = Path(sys.argv[1]), Path(sys.argv[2])
allow = {h.strip().lower().rstrip(".") for h in hosts.read_text().splitlines() if h.strip()}
kept = []
for line in web.read_text(errors="ignore").splitlines() if web.is_file() else []:
    raw = line.strip()
    if not raw:
        continue
    host = raw
    if "://" in raw:
        host = urlsplit(raw).hostname or ""
    host = host.split("/")[0].split(":")[0].lower().rstrip(".")
    if host in allow:
        kept.append(raw)
web.write_text("".join(f"{u}\n" for u in kept))
PY
  fi
  : > "$out/nuclei_output.jsonl"
  truncated=0
  deadline=$(( $(date +%s) + nuclei_budget ))
  for sev in "$sev_first" "$sev_rest"; do
    [ -n "$sev" ] || continue
    left=$(( deadline - $(date +%s) ))
    if [ "$left" -lt 8 ]; then
      truncated=1
      log "nuclei budget exhausted before severity $sev"
      break
    fi
    tmp="$out/nuclei-$sev.jsonl"
    tmp="${tmp//,/-}"
    set +e
    timeout "$left" nuclei -l "$webapps" -severity "$sev" \
      -rl "$nuclei_rl" -c "$nuclei_c" -bs "$nuclei_bs" -timeout 10 -retries 1 \
      -jsonl -o "$tmp" -silent 2>/dev/null
    nrc=$?
    set -e
    if [ "$nrc" -eq 124 ]; then truncated=1; fi
    if [ -f "$tmp" ]; then cat "$tmp" >> "$out/nuclei_output.jsonl"; fi
  done
  python3 - "$out" "$domain" "$truncated" "$nuclei_cap" "$nuclei_rl" <<'PY'
import json, sys
from pathlib import Path
out, domain = Path(sys.argv[1]), sys.argv[2]
timed_out = sys.argv[3] == "1"
cap = int(sys.argv[4])
rate = sys.argv[5]
rows = []
src = out / "nuclei_output.jsonl"
if src.is_file():
    for line in src.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        rows.append({
            "template": d.get("template-id", ""),
            "severity": (d.get("info") or {}).get("severity", ""),
            "host": d.get("host", ""),
            "matched_at": d.get("matched-at", ""),
            "description": (d.get("info") or {}).get("name", ""),
        })
total = len(rows)
truncated = timed_out or total > cap
if total > cap:
    rows = rows[:cap]
notes = []
if timed_out:
    notes.append("nuclei wall-clock budget expired; partial matches kept")
if total > cap:
    notes.append(f"nuclei result cap {cap} reached; kept {cap} of {total}")
notes.append(f"severity-first template scan at -rl {rate}")
summary = {
    "phase": "14-nuclei-scan",
    "domain": domain,
    "tools_run": ["nuclei"],
    "tools_skipped": [],
    "count": len(rows),
    "count_total": total,
    "degraded": bool(truncated),
    "truncated": bool(truncated),
    "items": rows,
    "notes": notes,
    "output_files": [str(src)],
}
(out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps({"phase": "14", "count": len(rows), "degraded": bool(truncated), "truncated": bool(truncated)}))
PY
else
  echo '{"phase":"14-nuclei-scan","domain":"'"$domain"'","tools_run":[],"tools_skipped":[{"tool":"nuclei","reason":"not installed"}],"count":0,"items":[],"notes":["0 templates loaded because nuclei is not installed. That is a coverage gap, not a clean target. run.sh scan applies the pinned in-repo rules."],"output_files":[]}' > "$out/summary.json"
fi

mark_done "$domain" "recon-14"
echo '{"phase":"14"}'
