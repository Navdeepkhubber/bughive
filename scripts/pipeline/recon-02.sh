#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"

domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/02-dns-resolution"
mkdir -p "$out"

cp "$hd/recon/01-subdomain-enum/all-hosts.txt" "$out/hosts.txt" 2>/dev/null || cp "$hd/scope.txt" "$out/hosts.txt"

python3 - "$out" "$hd" <<'PY'
import json, subprocess, sys
from pathlib import Path

out, hd = Path(sys.argv[1]), Path(sys.argv[2])
hosts = [h.strip() for h in (out/"hosts.txt").read_text().split() if h.strip()]
scope = set((hd/"scope.txt").read_text().split())
in_scope = [h for h in hosts if h in scope or any(h.endswith("."+s) or s.endswith("."+h) for s in scope)]

results = {}
for host in in_scope:
    rec = {}
    for rtype in ["A", "AAAA", "MX", "TXT", "CNAME", "NS"]:
        try:
            r = subprocess.run(["dig", "+short", rtype, host], capture_output=True, text=True, timeout=10)
            values = [v.strip() for v in r.stdout.splitlines() if v.strip()]
            if values: rec[rtype] = values
        except subprocess.TimeoutExpired:
            pass
    results[host] = rec

summary = {
    "phase": "02-dns-resolution",
    "domain": hd.name,
    "count": len(results),
    "records": results,
    "output_files": [str(out/"dns-records.json")],
}
(out/"dns-records.json").write_text(json.dumps(results, indent=2))
(out/"summary.json").write_text(json.dumps(summary, indent=2))
print(json.dumps({"phase":"02","hosts":len(results)}))
PY

mark_done "$domain" "recon-02"
