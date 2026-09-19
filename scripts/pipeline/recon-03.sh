#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"

domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/03-port-scan"
mkdir -p "$out"

python3 - "$out" "$hd" <<'PY'
import json, subprocess, sys
from pathlib import Path

out, hd = Path(sys.argv[1]), Path(sys.argv[2])
dns = json.loads((hd/"recon/02-dns-resolution/dns-records.json").read_text())

# Collect unique A records
ips = set()
for host, recs in dns.items():
    for ip in recs.get("A", []):
        ips.add(ip)
    for ip in recs.get("AAAA", []):
        ips.add(ip)

results = {}
for ip in sorted(ips):
    try:
        r = subprocess.run(
            ["nmap", "-sT", "-Pn", "--top-ports", "1000", "-oG", "-", ip],
            capture_output=True, text=True, timeout=300
        )
        ports = []
        for line in r.stdout.splitlines():
            if line.startswith("Host:") and "Ports:" in line:
                for p in line.split("Ports:")[1].split(","):
                    parts = p.strip().split("/")
                    if len(parts) >= 2 and parts[1] == "open":
                        ports.append(parts[0])
        results[ip] = {"open_ports": ports}
    except subprocess.TimeoutExpired:
        results[ip] = {"error": "timeout"}

summary = {
    "phase": "03-port-scan",
    "domain": hd.name,
    "count": len(results),
    "results": results,
    "output_files": [str(out/"ports.json")],
}
(out/"ports.json").write_text(json.dumps(results, indent=2))
(out/"summary.json").write_text(json.dumps(summary, indent=2))
print(json.dumps({"phase":"03","ips":len(results)}))
PY

mark_done "$domain" "recon-03"
