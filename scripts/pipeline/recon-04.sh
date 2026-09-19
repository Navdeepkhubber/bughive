#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"

domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/04-http-probe"
mkdir -p "$out"

python3 - "$out" "$hd" <<'PY'
import json, subprocess, sys
from pathlib import Path

out, hd = Path(sys.argv[1]), Path(sys.argv[2])
hosts = [h.strip() for h in (hd/"scope.txt").read_text().split() if h.strip()]

results = {}
for host in hosts:
    for scheme in ["https", "http"]:
        url = f"{scheme}://{host}"
        try:
            r = subprocess.run(
                ["curl", "-sI", "-m", "10", "-k", url],
                capture_output=True, text=True, timeout=15
            )
            if r.returncode == 0 and r.stdout:
                headers = {}
                status_line = r.stdout.splitlines()[0] if r.stdout else ""
                for line in r.stdout.splitlines()[1:]:
                    if ":" in line:
                        k, _, v = line.partition(":")
                        headers[k.strip().lower()] = v.strip()
                results[host] = {
                    "url": url,
                    "status_line": status_line,
                    "server": headers.get("server", ""),
                    "content_type": headers.get("content-type", ""),
                    "location": headers.get("location", ""),
                }
                break
        except subprocess.TimeoutExpired:
            pass

summary = {
    "phase": "04-http-probe",
    "domain": hd.name,
    "count": len(results),
    "results": results,
    "output_files": [str(out/"http.json")],
}
(out/"http.json").write_text(json.dumps(results, indent=2))
(out/"summary.json").write_text(json.dumps(summary, indent=2))
print(json.dumps({"phase":"04","hosts":len(results)}))
PY

mark_done "$domain" "recon-04"
