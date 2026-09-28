#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"

domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/02-dns-resolution"
script_dir="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$out"

# Prefer the scope-verified, wildcard-expanded asset list from phase 01.
# Falling back to raw discoveries (or the scope file) is still re-filtered through
# _scope.py below, so a wildcard can never be resolved as if it were a hostname.
assets="$hd/recon/01-subdomain-enum/assets.txt"
raw="$hd/recon/01-subdomain-enum/all-hosts.txt"
if [ -s "$assets" ]; then
  cp "$assets" "$out/hosts.txt"
elif [ -s "$raw" ]; then
  cp "$raw" "$out/hosts.txt"
else
  cp "$hd/scope.txt" "$out/hosts.txt"
fi

python3 - "$out" "$hd" "$script_dir" <<'PY'
import json, subprocess, sys
from pathlib import Path

sys.path.insert(0, sys.argv[3])
from _scope import scope_allows

out, hd = Path(sys.argv[1]), Path(sys.argv[2])
scope_text = (hd / "scope.txt").read_text()
hosts = [h.strip() for h in (out / "hosts.txt").read_text().split() if h.strip()]

# Re-check scope here too: this phase decides what gets a DNS query, and DNS is
# still traffic against the target's infrastructure.
in_scope, refused = [], []
for host in hosts:
    ok, _reason = scope_allows(scope_text, host)
    (in_scope if ok else refused).append(host)

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

resolved = sorted(h for h, rec in results.items() if rec.get("A") or rec.get("AAAA") or rec.get("CNAME"))
summary = {
    "phase": "02-dns-resolution",
    "domain": hd.name,
    "count": len(results),
    "count_resolved": len(resolved),
    "resolved": resolved,
    "refused_out_of_scope": refused,
    "records": results,
    "output_files": [str(out / "dns-records.json")],
}
(out / "dns-records.json").write_text(json.dumps(results, indent=2))
(out / "summary.json").write_text(json.dumps(summary, indent=2))
print(json.dumps({"phase": "02", "hosts": len(results), "resolved": len(resolved)}))
PY

mark_done "$domain" "recon-02"
