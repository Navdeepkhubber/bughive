#!/usr/bin/env bash
# Phase 09 — historical URLs (gau / waybackurls / Wayback CDX). Forgotten
# endpoints are a primary source of real bounty bugs; the stub dropped them.
#
# One batched gau invocation over a few registrable domains, inside a phase
# budget. A timeout or a cap still writes summary.json with degraded:true so
# the phase is not re-queued as if it never ran.
set -euo pipefail
source "$(dirname "$0")/_common.sh"
domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/09-historical-data"
script_dir="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$out"

python3 - "$out" "$hd" "$script_dir" <<'PY'
import json, os, shutil, subprocess, sys, time
from pathlib import Path

sys.path.insert(0, sys.argv[3])
from _scope import enum_roots
from _recon_io import merge_endpoints, url_in_scope, cap_items, write_json, param_urls_from, host_of
from _recon_safety import unique_registrable_roots
from _batch import knob, knob_int

out, hd = Path(sys.argv[1]), Path(sys.argv[2])
scope_text = (hd / "scope.txt").read_text() if (hd / "scope.txt").is_file() else ""

def clamp_int(raw, default, lo, hi):
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return max(lo, min(hi, value))

# Standalone hunts keep the short root cap from the termination fix.
# BUGHIVE_PASSIVE_WIDE=1 (the tranche runner) lifts that cap and relies on the
# per-host URL cap plus this wall clock instead.
budget = knob_int("BUGHIVE_GAU_BUDGET_SECONDS", 300, lo=30)
if os.environ.get("BUGHIVE_RECON09_BUDGET"):
    budget = clamp_int(os.environ.get("BUGHIVE_RECON09_BUDGET"), budget, 30, max(budget, 180))
wide = str(os.environ.get("BUGHIVE_PASSIVE_WIDE") or "").strip().lower() in {"1", "true", "yes", "on"}
if wide:
    root_limit = knob_int("BUGHIVE_GAU_MAX_ROOTS", 1000000, lo=1)
else:
    root_limit = clamp_int(os.environ.get("BUGHIVE_GAU_MAX_ROOTS"), 4, 1, 6)
gau_threads = knob_int("BUGHIVE_GAU_THREADS", 5, lo=1)
gau_providers = str(knob("BUGHIVE_GAU_PROVIDERS", "wayback") or "wayback")
gau_blacklist = str(knob("BUGHIVE_GAU_BLACKLIST", "") or "")
url_cap = knob_int("BUGHIVE_PASSIVE_URL_CAP", 1500, lo=1)
deadline = time.monotonic() + budget

tools_run, tools_skipped = [], []
raw_urls: list[str] = []
notes = [
    "Archive URLs may 404 today; they still name forgotten parameters and paths.",
    "Merged into recon/all_endpoints (capped).",
]
degraded = False
roots: list[str] = []

def remain() -> float:
    return deadline - time.monotonic()

try:
    candidates = enum_roots(scope_text) or [hd.name]
    roots, total_regs = unique_registrable_roots(candidates, root_limit)
    if total_regs > len(roots):
        degraded = True
        notes.append(
            f"capped historical roots to {len(roots)} registrable domains ({total_regs} in scope)"
        )
    if not roots:
        degraded = True
        notes.append("no registrable enumeration roots; refused to query public suffixes")

    def run_stdin(name, args):
        global degraded
        if not roots:
            return
        if not shutil.which(name):
            tools_skipped.append({"tool": name, "reason": "not installed"})
            return
        left = remain()
        if left < 8:
            degraded = True
            tools_skipped.append({"tool": name, "reason": "phase budget exhausted"})
            return
        tools_run.append(name)
        dest = out / f"{name}.txt"
        try:
            with open(dest, "w") as fh:
                proc = subprocess.run(
                    args,
                    input="\n".join(roots) + "\n",
                    text=True,
                    stdout=fh,
                    stderr=subprocess.DEVNULL,
                    timeout=max(8, min(left, budget)),
                    check=False,
                )
            if proc.returncode != 0:
                degraded = True
                notes.append(f"{name} exited {proc.returncode}; partial output kept")
        except subprocess.TimeoutExpired:
            degraded = True
            notes.append(f"{name} timed out; partial output kept")
        except FileNotFoundError:
            tools_skipped.append({"tool": name, "reason": "not installed"})
            return
        if dest.is_file():
            raw_urls.extend(dest.read_text(errors="ignore").splitlines())

    # gau reads domains on stdin. One process, not one per host.
    # --blacklist drops static assets; --providers keeps the pull on wayback
    # unless the operator overrides BUGHIVE_GAU_PROVIDERS.
    gau_args = ["gau", "--subs", "--threads", str(gau_threads), "--providers", gau_providers, "--timeout", "20"]
    if gau_blacklist:
        gau_args.extend(["--blacklist", gau_blacklist])
    run_stdin("gau", gau_args)
    run_stdin("waybackurls", ["waybackurls"])

    if "gau" not in tools_run and "waybackurls" not in tools_run and roots and remain() >= 8:
        tools_run.append("wayback-cdx")
        for root in roots:
            if remain() < 8:
                degraded = True
                notes.append("wayback CDX stopped at the phase budget")
                break
            api = (
                "https://web.archive.org/cdx/search/cdx"
                f"?url=*.{root}/*&output=json&fl=original&collapse=urlkey&limit=500"
            )
            try:
                from urllib.request import Request, urlopen
                req = Request(api, headers={"User-Agent": "bh-recon/0.1 (authorized; passive archive lookup)"})
                with urlopen(req, timeout=max(5, min(20, int(remain())))) as resp:
                    data = json.loads(resp.read().decode("utf-8", "replace") or "[]")
                for row in data[1:] if data and isinstance(data[0], list) else data:
                    if isinstance(row, list) and row:
                        raw_urls.append(row[0])
                    elif isinstance(row, str):
                        raw_urls.append(row)
            except Exception as exc:
                degraded = True
                tools_skipped.append({"tool": "wayback-cdx", "reason": str(exc)[:200]})
                break
except Exception as exc:
    degraded = True
    notes.append(f"phase error: {exc}"[:300])

in_scope = []
seen = set()
for u in raw_urls:
    u = u.strip()
    if not u.startswith("http") or u in seen:
        continue
    if not url_in_scope(scope_text, u):
        continue
    seen.add(u)
    in_scope.append(u)

per_host: dict[str, int] = {}
capped_urls = []
dropped_urls = 0
for u in in_scope:
    host = host_of(u) or ""
    per_host[host] = per_host.get(host, 0) + 1
    if per_host[host] <= url_cap:
        capped_urls.append(u)
    else:
        dropped_urls += 1
if dropped_urls:
    degraded = True
    notes.append(
        f"per-host passive URL cap {url_cap} truncated {dropped_urls} url(s); partial list kept"
    )
in_scope = capped_urls
truncated = bool(degraded and (dropped_urls or any("timed out" in n or "budget" in n for n in notes)))
(out / "urls.txt").write_text("".join(f"{u}\n" for u in in_scope))
params = param_urls_from(in_scope)
(out / "param_urls.txt").write_text("".join(f"{u}\n" for u in params))
try:
    merge_endpoints(hd, in_scope[:5000], scope_text)
except Exception as exc:
    degraded = True
    notes.append(f"endpoint merge failed: {exc}"[:200])

items = [{"url": u, "has_params": ("?" in u and "=" in u)} for u in in_scope[:200]]
summary = {
    "phase": "09-historical-data",
    "domain": hd.name,
    "degraded": bool(degraded),
    "truncated": bool(truncated),
    "passive_url_cap": url_cap,
    "roots": roots,
    "tools_run": tools_run,
    "tools_skipped": tools_skipped,
    "count": len(in_scope),
    "param_url_count": len(params),
    "items": cap_items(items),
    "notes": notes,
    "output_files": [str(out / "urls.txt"), str(out / "param_urls.txt")],
}
write_json(out / "summary.json", summary)
print(json.dumps({
    "phase": "09",
    "count": len(in_scope),
    "param_urls": len(params),
    "degraded": bool(degraded),
    "truncated": bool(truncated),
    "roots": len(roots),
}))
PY

mark_done "$domain" "recon-09"
