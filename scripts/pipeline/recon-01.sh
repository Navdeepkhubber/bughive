#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"

domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/01-subdomain-enum"
mkdir -p "$out"
cp "$hd/scope.txt" "$out/scope.txt"

# Passive enumeration — subfinder if present, else skip
tools_run=()
tools_skipped=()

if command -v subfinder >/dev/null 2>&1; then
  log "subfinder $domain (passive)"
  timeout 60 subfinder -d "$domain" -silent -o "$out/raw-subfinder.txt" 2>/dev/null || true
  tools_run+=("subfinder")
else
  tools_skipped+=('{"tool":"subfinder","reason":"not installed"}')
fi

# Deduplicate
if [ -f "$out/raw-subfinder.txt" ]; then
  sort -u "$out/raw-subfinder.txt" -o "$out/all-hosts.txt"
else
  : > "$out/all-hosts.txt"
fi

total=$(wc -l < "$out/all-hosts.txt" | tr -d ' ')

# Partition
python3 - "$out" "$hd" <<'PY'
import json, sys
from pathlib import Path

out, hd = Path(sys.argv[1]), Path(sys.argv[2])
scope = set((hd / "scope.txt").read_text().split())
all_hosts = set((out / "all-hosts.txt").read_text().split()) if (out/"all-hosts.txt").exists() else set()

confirmed = sorted(all_hosts & scope)
missing = sorted(scope - all_hosts)
out_of_scope = sorted(all_hosts - scope)

summary = {
    "phase": "01-subdomain-enum",
    "domain": hd.name,
    "mode": "passive",
    "count_total_discovered": len(all_hosts),
    "in_scope_confirmed": confirmed,
    "in_scope_missing": missing,
    "out_of_scope_count": len(out_of_scope),
    "out_of_scope_found": out_of_scope[:100],
    "output_files": [str(out/"all-hosts.txt"), str(out/"scope.txt")],
}
(out / "summary.json").write_text(json.dumps(summary, indent=2))
print(json.dumps({"phase":"01","count":len(all_hosts),"confirmed":len(confirmed),"out_of_scope":len(out_of_scope)}))
PY

mark_done "$domain" "recon-01"
