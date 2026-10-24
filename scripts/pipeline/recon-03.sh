#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"

domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/03-port-scan"
script_dir="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$out"

python3 - "$out" "$hd" "$script_dir" <<'PY'
import json, os, subprocess, sys, time
from pathlib import Path

sys.path.insert(0, sys.argv[3])
from _recon_safety import is_scannable_public_ip

out, hd = Path(sys.argv[1]), Path(sys.argv[2])
dns_path = hd / "recon" / "02-dns-resolution" / "dns-records.json"

def clamp_int(raw, default, lo, hi):
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return max(lo, min(hi, value))

max_ips = clamp_int(os.environ.get("PORT_SCAN_MAX_IPS"), 16, 1, 20)
top_ports = clamp_int(os.environ.get("PORT_SCAN_TOP_PORTS"), 150, 100, 200)
per_ip = clamp_int(os.environ.get("PORT_SCAN_IP_TIMEOUT"), 60, 15, 90)
budget = clamp_int(os.environ.get("PORT_SCAN_BUDGET"), 150, 30, 240)

notes = []
results = {}
ips = []
nonpublic = []
capped = []
skipped_budget = 0
nmap_missing = False
degraded = False

def emit(summary_notes, degraded_flag):
    summary = {
        "phase": "03-port-scan",
        "domain": hd.name,
        "count": len(results),
        "degraded": bool(degraded_flag),
        "ips_seen": len(ips),
        "ips_skipped_nonpublic": len(nonpublic),
        "ips_skipped_cap": max(0, len([ip for ip in ips if is_scannable_public_ip(ip)]) - len(capped)),
        "ips_skipped_budget": skipped_budget,
        "ips_scanned": len(results),
        "skipped_nonpublic_sample": nonpublic[:8],
        "port_scan_max_ips": max_ips,
        "top_ports": top_ports,
        "per_ip_timeout": per_ip,
        "tools_run": [] if nmap_missing or not results else ["nmap"],
        "notes": summary_notes,
        "results": results,
        "output_files": [str(out / "ports.json")],
    }
    (out / "ports.json").write_text(json.dumps(results, indent=2))
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({
        "phase": "03",
        "ips": len(results),
        "degraded": summary["degraded"],
        "skipped_nonpublic": summary["ips_skipped_nonpublic"],
        "skipped_cap": summary["ips_skipped_cap"],
    }))

if not dns_path.is_file():
    notes.append("dns-records.json missing; port scan skipped rather than guessing addresses")
    emit(notes, True)
    sys.exit(0)

try:
    dns = json.loads(dns_path.read_text() or "{}")
except json.JSONDecodeError as exc:
    notes.append(f"dns-records.json unreadable: {exc}")
    emit(notes, True)
    sys.exit(0)

seen = []
for _host, recs in (dns or {}).items() if isinstance(dns, dict) else []:
    if not isinstance(recs, dict):
        continue
    for key in ("A", "AAAA"):
        values = recs.get(key) or []
        if isinstance(values, str):
            values = [values]
        for ip in values:
            ip = str(ip).strip()
            if ip and ip not in seen:
                seen.append(ip)
ips = seen

public = []
for ip in ips:
    if is_scannable_public_ip(ip):
        public.append(ip)
    else:
        nonpublic.append(ip)
public.sort()
nonpublic.sort()
capped = public[:max_ips]
skipped_cap = len(public) - len(capped)

if nonpublic:
    notes.append(
        f"skipped {len(nonpublic)} non-public address(es) "
        "(private, loopback, link-local, multicast, or reserved)"
    )
if skipped_cap:
    notes.append(f"capped public scan at {max_ips}; skipped {skipped_cap} additional public address(es)")
    degraded = True
if not ips:
    notes.append("no A/AAAA addresses in dns-records.json")
elif not capped:
    notes.append("no public addresses left after skipping non-public ranges")
    degraded = True

deadline = time.monotonic() + budget
for ip in capped:
    if time.monotonic() > deadline:
        break
    try:
        r = subprocess.run(
            ["nmap", "-sT", "-Pn", "--top-ports", str(top_ports), "-oG", "-", ip],
            capture_output=True, text=True, timeout=per_ip,
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
    except FileNotFoundError:
        nmap_missing = True
        notes.append("nmap is not installed; no ports were scanned")
        degraded = True
        break

skipped_budget = len([ip for ip in capped if ip not in results and not nmap_missing])
if skipped_budget:
    notes.append(f"phase budget stopped the scan; {skipped_budget} public address(es) not scanned")
    degraded = True

emit(notes, degraded)
PY

mark_done "$domain" "recon-03"
