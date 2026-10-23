#!/usr/bin/env bash
# Phase 09 — historical URLs (gau / waybackurls / Wayback CDX). Forgotten
# endpoints are a primary source of real bounty bugs; the stub dropped them.
set -euo pipefail
source "$(dirname "$0")/_common.sh"
domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/09-historical-data"
script_dir="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$out"

python3 - "$out" "$hd" "$script_dir" <<'PY'
import json, shutil, subprocess, sys
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

sys.path.insert(0, sys.argv[3])
from _scope import enum_roots
from _recon_io import merge_endpoints, url_in_scope, cap_items, write_json, param_urls_from

out, hd = Path(sys.argv[1]), Path(sys.argv[2])
scope_text = (hd / "scope.txt").read_text()
roots = enum_roots(scope_text) or [hd.name]
tools_run, tools_skipped = [], []
raw_urls: list[str] = []


def run_tool(name, args, dest):
    if not shutil.which(name):
        tools_skipped.append({"tool": name, "reason": "not installed"})
        return False
    tools_run.append(name)
    try:
        with open(dest, "w") as fh:
            subprocess.run(args, timeout=180, check=False, stdout=fh, stderr=subprocess.DEVNULL)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
    return dest.is_file()


for root in roots[:8]:
    if run_tool("gau", ["gau", "--subs", root], out / f"gau-{root}.txt"):
        raw_urls.extend((out / f"gau-{root}.txt").read_text(errors="ignore").splitlines())
    if run_tool("waybackurls", ["waybackurls", root], out / f"waybackurls-{root}.txt"):
        raw_urls.extend((out / f"waybackurls-{root}.txt").read_text(errors="ignore").splitlines())

if "gau" not in tools_run and "waybackurls" not in tools_run:
    tools_run.append("wayback-cdx")
    for root in roots[:5]:
        api = f"https://web.archive.org/cdx/search/cdx?url=*.{root}/*&output=json&fl=original&collapse=urlkey&limit=2000"
        try:
            req = Request(api, headers={"User-Agent": "bh-recon/0.1 (authorized; passive archive lookup)"})
            with urlopen(req, timeout=40) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace") or "[]")
            for row in data[1:] if data and isinstance(data[0], list) else data:
                if isinstance(row, list) and row:
                    raw_urls.append(row[0])
                elif isinstance(row, str):
                    raw_urls.append(row)
        except Exception as e:
            tools_skipped.append({"tool": "wayback-cdx", "reason": str(e)[:200]})

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

(out / "urls.txt").write_text("".join(f"{u}\n" for u in in_scope))
params = param_urls_from(in_scope)
(out / "param_urls.txt").write_text("".join(f"{u}\n" for u in params))
merge_endpoints(hd, in_scope[:5000], scope_text)

items = [{"url": u, "has_params": ("?" in u and "=" in u)} for u in in_scope[:200]]
summary = {
    "phase": "09-historical-data",
    "domain": hd.name,
    "tools_run": tools_run,
    "tools_skipped": tools_skipped,
    "count": len(in_scope),
    "param_url_count": len(params),
    "items": cap_items(items),
    "notes": [
        "Archive URLs may 404 today; they still name forgotten parameters and paths.",
        "Merged into recon/all_endpoints (capped).",
    ],
    "output_files": [str(out / "urls.txt"), str(out / "param_urls.txt")],
}
write_json(out / "summary.json", summary)
print(json.dumps({"phase": "09", "count": len(in_scope), "param_urls": len(params)}))
PY

mark_done "$domain" "recon-09"
