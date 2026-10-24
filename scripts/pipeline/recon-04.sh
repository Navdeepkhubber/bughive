#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"

domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/04-http-probe"
script_dir="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$out"

# Common alt-HTTP ports beyond 80/443 -- admin panels, Jenkins, and dev
# servers live here. Pulled from real bug-bounty methodology, not just the
# generic top-1000 default the port scan (phase 03) already covers.
ALT_PORTS="3000,5000,7001,7002,8000,8008,8009,8080,8081,8082,8088,8181,8443,8880,8888,9000,9090,9443,10000"

# Probe only concrete, scope-verified hosts. Feeding the literal pattern
# `*.synedra.com` to httpx used to make this phase a no-op.
assets="$hd/recon/01-subdomain-enum/assets.txt"
raw="$hd/recon/01-subdomain-enum/all-hosts.txt"
: > "$out/hosts.txt"
if [ -s "$assets" ]; then
  cp "$assets" "$out/hosts.txt"
elif [ -s "$raw" ]; then
  python3 "$script_dir/_scope.py" filter "$hd/scope.txt" < "$raw" > "$out/hosts.txt" 2>/dev/null || : > "$out/hosts.txt"
else
  python3 "$script_dir/_scope.py" roots "$hd/scope.txt" > "$out/hosts.txt" 2>/dev/null || : > "$out/hosts.txt"
fi

# Probe only names that actually resolved. Unresolved hosts burn the httpx
# budget and a timeout then looks like a clean, tiny result set.
dns_records="$hd/recon/02-dns-resolution/dns-records.json"
if [ -s "$dns_records" ] && [ -s "$out/hosts.txt" ]; then
  python3 - "$out/hosts.txt" "$dns_records" "$out/hosts-unresolved.txt" <<'PY'
import json, sys
from pathlib import Path
hosts_path, dns_path, dropped_path = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
hosts = [h.strip() for h in hosts_path.read_text().split() if h.strip()]
try:
    dns = json.loads(dns_path.read_text() or "{}")
except json.JSONDecodeError:
    dns = {}
resolved = set()
if isinstance(dns, dict):
    for host, recs in dns.items():
        if not isinstance(recs, dict):
            continue
        addrs = []
        for key in ("A", "AAAA"):
            values = recs.get(key) or []
            if isinstance(values, str):
                values = [values]
            addrs.extend(values)
        if any(str(v).strip() for v in addrs):
            resolved.add(str(host).strip().lower().rstrip("."))
kept, dropped = [], []
for host in hosts:
    (kept if host.lower().rstrip(".") in resolved else dropped).append(host)
hosts_path.write_text("".join(f"{h}\n" for h in kept))
dropped_path.write_text("".join(f"{h}\n" for h in dropped))
print(json.dumps({"kept": len(kept), "dropped": len(dropped)}))
PY
fi

# grep -c exits 1 when the count is 0, so `|| echo` would append a second 0
# and the numeric test would not see an empty host file.
host_count=$(grep -c . "$out/hosts.txt" 2>/dev/null || true)
host_count=${host_count:-0}
if [ "$host_count" -eq 0 ]; then
  log "no concrete resolved in-scope hosts to probe"
  RECON_OUT="$out" RECON_DOMAIN="$domain" python3 - <<'PY'
import json, os
from pathlib import Path
out = Path(os.environ["RECON_OUT"])
unres = out / "hosts-unresolved.txt"
n = 0
if unres.is_file():
    n = sum(1 for line in unres.read_text().splitlines() if line.strip())
notes = ["no concrete in-scope hosts; nothing was probed. Run recon-01 with a working subdomain source before treating HTTP probing as complete."]
if n:
    notes.append(f"{n} host(s) had no A/AAAA record and were not probed")
doc = {
    "phase": "04-http-probe",
    "domain": os.environ["RECON_DOMAIN"],
    "tools_run": [],
    "tools_skipped": [],
    "count": 0,
    "hosts_probed": 0,
    "hosts_unresolved": n,
    "degraded": True,
    "results": {},
    "notes": notes,
    "output_files": [],
}
(out / "summary.json").write_text(json.dumps(doc, indent=2) + "\n")
PY
  mark_done "$domain" "recon-04"
  echo '{"phase":"04","hosts":0,"degraded":true}'
  exit 0
fi

if command -v httpx >/dev/null 2>&1; then
  eval "$(python3 "$script_dir/_batch.py" exports)"
  alt_n=$(awk -F, '{print NF}' <<<"$ALT_PORTS")
  ports=$((alt_n + 2))
  wall=$((host_count * ports * 8 / 50 + 30))
  if [ "$wall" -lt 45 ]; then wall=45; fi
  wall_cap="${BUGHIVE_HTTPX_BUDGET_SECONDS:-300}"
  if [ "$wall" -gt "$wall_cap" ]; then wall="$wall_cap"; fi
  httpx_threads="${BUGHIVE_HTTPX_THREADS:-50}"
  httpx_rate="${BUGHIVE_HTTPX_RATE:-150}"
  tech_args=()
  if [ "${BUGHIVE_HTTPX_TECH_DETECT:-1}" = "1" ] && httpx -h 2>&1 | grep -q -- '-tech-detect'; then
    tech_args+=(-tech-detect)
  fi
  log "httpx probing $host_count resolved in-scope host(s) (-t $httpx_threads -rl $httpx_rate, wall ${wall}s)"
  set +e
  timeout "$wall" httpx -l "$out/hosts.txt" -p "80,443,$ALT_PORTS" \
    -timeout 8 -retries 1 -t "$httpx_threads" -rl "$httpx_rate" \
    ${tech_args[@]+"${tech_args[@]}"} \
    -silent -json -o "$out/httpx.jsonl" 2>/dev/null
  httpx_rc=$?
  set -e
  echo "$httpx_rc" > "$out/httpx.rc"
fi

python3 - "$out" "$hd" "$script_dir" "$ALT_PORTS" <<'PY'
import json, subprocess, sys
from pathlib import Path

sys.path.insert(0, sys.argv[3])
from _scope import scope_allows
from _recon_safety import httpx_truncated
from _batch import apply_bounds, knob_int

out, hd, alt_ports_csv = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[4]
scope_text = (hd / "scope.txt").read_text()
hosts = [h.strip() for h in (out / "hosts.txt").read_text().split() if h.strip()]
hosts = [h for h in hosts if scope_allows(scope_text, h)[0]]
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
flat = []
for host, rows in results.items():
    for row in rows:
        flat.append((host, row))
bounded = apply_bounds(
    flat,
    result_cap=knob_int("BUGHIVE_HTTPX_RESULT_CAP", 400, lo=1),
    exit_code=None,
)
if bounded["truncated"] and bounded["count"] < bounded["count_total"]:
    trimmed = {}
    for host, row in bounded["results"]:
        trimmed.setdefault(host, []).append(row)
    results = trimmed
    count = bounded["count"]
httpx_rc = None
rc_path = out / "httpx.rc"
if rc_path.is_file():
    try:
        httpx_rc = int(rc_path.read_text().strip() or "-1")
    except ValueError:
        httpx_rc = None
unresolved = []
unres_path = out / "hosts-unresolved.txt"
if unres_path.is_file():
    unresolved = [h.strip() for h in unres_path.read_text().splitlines() if h.strip()]
httpx_produced = httpx_file.exists() and httpx_file.stat().st_size > 0
raw_count = bounded["count_total"]
ratio_truncated = httpx_rc is not None and httpx_truncated(httpx_rc, len(hosts), raw_count)
truncated = bool(bounded["truncated"] or ratio_truncated)
notes = list(bounded["reasons"])
if not hosts:
    notes.append("no in-scope hosts left to probe")
if unresolved:
    notes.append(f"{len(unresolved)} unresolved host(s) were not probed")
if truncated:
    notes.append(
        f"httpx truncated (rc={httpx_rc}, responses={count}, hosts_probed={len(hosts)}); "
        "partial output is not a clean success"
    )
summary = {
    "phase": "04-http-probe",
    "domain": hd.name,
    "hosts_probed": len(hosts),
    "hosts_unresolved": len(unresolved),
    "httpx_rc": httpx_rc,
    "truncated": bool(truncated),
    "degraded": bool(truncated or not hosts),
    "tools_run": [] if ratio_truncated or not httpx_produced else ["httpx"],
    "tools_skipped": [] if httpx_file.exists() or truncated else [{"tool": "httpx", "reason": "not installed; curl fallback used, alt-port sweep skipped"}],
    "count": count,
    "results": results,
    "notes": notes,
    "output_files": [str(out / "http.json")],
}
(out / "http.json").write_text(json.dumps(results, indent=2))
(out / "summary.json").write_text(json.dumps(summary, indent=2))
print(json.dumps({
    "phase": "04",
    "hosts_probed": len(hosts),
    "responses": count,
    "degraded": summary["degraded"],
    "truncated": bool(truncated),
}))
PY

mark_done "$domain" "recon-04"
