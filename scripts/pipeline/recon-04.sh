#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"

domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/04-http-probe"
mkdir -p "$out"

# Common alt-HTTP ports beyond 80/443 -- admin panels, Jenkins, and dev
# servers live here. Pulled from real bug-bounty methodology, not just the
# generic top-1000 default the port scan (phase 03) already covers.
ALT_PORTS="3000,5000,7001,7002,8000,8008,8009,8080,8081,8082,8088,8181,8443,8880,8888,9000,9090,9443,10000"

if command -v httpx >/dev/null 2>&1; then
  log "httpx probing $domain scope (80,443 + alt ports)"
  timeout 120 httpx -l "$hd/scope.txt" -p "80,443,$ALT_PORTS" -silent -json -o "$out/httpx.jsonl" 2>/dev/null || true
fi

python3 - "$out" "$hd" "$ALT_PORTS" <<'PY'
import json, subprocess, sys
from pathlib import Path

out, hd, alt_ports_csv = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
hosts = [h.strip() for h in (hd/"scope.txt").read_text().split() if h.strip()]
alt_ports = [p for p in alt_ports_csv.split(",") if p]

# If httpx already produced results, use those and skip the slow curl fallback.
httpx_file = out / "httpx.jsonl"
results = {}
if httpx_file.exists() and httpx_file.stat().st_size > 0:
    for line in httpx_file.read_text().splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = row.get("host") or row.get("input", "")
        results.setdefault(host, []).append({
            "url": row.get("url", ""),
            "status_code": row.get("status_code"),
            "title": row.get("title", ""),
            "webserver": row.get("webserver", ""),
            "content_type": row.get("content_type", ""),
        })
    # Protocol-only-duplicate cleanup: httpx probes 80 and 443 as separate
    # targets, so the same host commonly shows up twice with identical
    # status/title differing only in http:// vs https://. Keep https when
    # both exist on the default ports with the same status code -- this
    # mirrors the "clean the webapps file" step in the reference
    # methodology and halves downstream fuzzing/crawling work for no loss.
    for host, rows in results.items():
        by_status = {}
        for r in rows:
            by_status.setdefault(r.get("status_code"), []).append(r)
        deduped = []
        for status, group in by_status.items():
            https_rows = [r for r in group if r["url"].startswith("https://")]
            http_rows = [r for r in group if r["url"].startswith("http://")]
            if https_rows and http_rows:
                deduped.extend(https_rows)  # drop the http:// twin(s)
            else:
                deduped.extend(group)
        results[host] = deduped
else:
    # Fallback: curl -sI per host, per port, https then http on 80/443 only
    # (curl fallback intentionally skips the alt-port sweep -- that's a lot
    # of serial requests without httpx's concurrency; note the limitation).
    for host in hosts:
        for scheme in ["https", "http"]:
            url = f"{scheme}://{host}"
            try:
                r = subprocess.run(["curl", "-sI", "-m", "10", "-k", url], capture_output=True, text=True, timeout=15)
                if r.returncode == 0 and r.stdout:
                    headers = {}
                    status_line = r.stdout.splitlines()[0] if r.stdout else ""
                    for line in r.stdout.splitlines()[1:]:
                        if ":" in line:
                            k, _, v = line.partition(":")
                            headers[k.strip().lower()] = v.strip()
                    results[host] = [{
                        "url": url, "status_line": status_line,
                        "server": headers.get("server", ""),
                        "content_type": headers.get("content-type", ""),
                        "location": headers.get("location", ""),
                    }]
                    break
            except subprocess.TimeoutExpired:
                pass

count = sum(len(v) for v in results.values())
summary = {
    "phase": "04-http-probe",
    "domain": hd.name,
    "tools_run": ["httpx"] if httpx_file.exists() and httpx_file.stat().st_size > 0 else [],
    "tools_skipped": [] if httpx_file.exists() else [{"tool": "httpx", "reason": "not installed; curl fallback used, alt-port sweep skipped"}],
    "count": count,
    "results": results,
    "output_files": [str(out/"http.json")],
}
(out/"http.json").write_text(json.dumps(results, indent=2))
(out/"summary.json").write_text(json.dumps(summary, indent=2))
print(json.dumps({"phase":"04","hosts":count}))
PY

mark_done "$domain" "recon-04"
