#!/usr/bin/env bash
# Phase 06 — parameter discovery. Without this, recon-15 has an empty param_urls
# file and XSS/SSTI/SSRF one-liners never fire.
set -euo pipefail
source "$(dirname "$0")/_common.sh"
domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/06-param-discovery"
script_dir="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$out"

python3 - "$out" "$hd" "$script_dir" <<'PY'
import json, re, shutil, subprocess, sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from html.parser import HTMLParser

sys.path.insert(0, sys.argv[3])
from _recon_io import live_urls, merge_endpoints, url_in_scope, cap_items, write_json, read_json

out, hd = Path(sys.argv[1]), Path(sys.argv[2])
scope_text = (hd / "scope.txt").read_text()
tools_run, tools_skipped = [], []
items = []
seen = set()


def add(url, param, source):
    key = (url.split("#")[0], param)
    if key in seen:
        return
    if not url_in_scope(scope_text, url):
        return
    seen.add(key)
    items.append({"url": url.split("#")[0], "param": param, "source": source})


# URLs already known
pool = []
ep = hd / "recon" / "all_endpoints"
if ep.is_file():
    pool.extend(l.strip() for l in ep.read_text().splitlines() if l.strip())
pool.extend(live_urls(hd))
katana = hd / "recon" / "05-content-discovery" / "katana.txt"
if katana.is_file():
    pool.extend(l.strip() for l in katana.read_text().splitlines() if l.strip())

for url in pool:
    if "?" not in url or "=" not in url:
        continue
    qs = parse_qs(urlparse(url).query, keep_blank_values=True)
    for name in qs:
        add(url, name, "querystring")

# Forms in response cache / phase-05 bodies are not always present; parse cached HTML.
cache = hd / "recon" / "12-response-cache"
class FormParser(HTMLParser):
    def __init__(self, base):
        super().__init__()
        self.base = base
        self.action = None
        self.names = []

    def handle_starttag(self, tag, attrs):
        ad = dict(attrs)
        if tag == "form":
            self.action = ad.get("action") or self.base
        if tag in ("input", "select", "textarea") and ad.get("name"):
            self.names.append(ad["name"])

if cache.is_dir():
    tools_run.append("form-parse")
    for body in list(cache.glob("*.body"))[:80]:
        text = body.read_text(errors="ignore")[:200_000]
        if "<form" not in text.lower():
            continue
        p = FormParser("")
        try:
            p.feed(text)
        except Exception:
            continue
        action = p.action or ""
        if action.startswith("http"):
            for n in p.names:
                add(action, n, "html-form")

# JS analyzer endpoints (relative or absolute)
js_ep = hd / "recon" / "07-js-analysis" / "endpoints.txt"
if js_ep.is_file():
    tools_run.append("js-endpoints")
    for line in js_ep.read_text().splitlines():
        line = line.strip()
        if "?" in line and "=" in line and line.startswith("http"):
            qs = parse_qs(urlparse(line).query, keep_blank_values=True)
            for name in qs:
                add(line, name, "js-endpoint")

# Optional arjun on a tiny sample of live URLs (expensive; cap hard).
if shutil.which("arjun"):
    tools_run.append("arjun")
    sample = live_urls(hd)[:5]
    arjun_in = out / "arjun-in.txt"
    arjun_in.write_text("".join(f"{u}\n" for u in sample))
    arjun_out = out / "arjun.json"
    try:
        subprocess.run(
            ["arjun", "-i", str(arjun_in), "-oJ", str(arjun_out), "-t", "8", "--passive"],
            timeout=120,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    data = read_json(arjun_out, {})
    # arjun formats vary; accept {url: [params]} or list
    if isinstance(data, dict):
        for url, params in data.items():
            if url in ("ok", "error"):
                continue
            names = params if isinstance(params, list) else (params.get("params") or []) if isinstance(params, dict) else []
            for n in names:
                add(url, str(n), "arjun")
else:
    tools_skipped.append({"tool": "arjun", "reason": "not installed; querystrings + forms + JS used"})

# Write param URL list for recon-15
param_urls = sorted({i["url"] for i in items if "?" in i["url"]})
(out / "param_urls.txt").write_text("".join(f"{u}\n" for u in param_urls))
merge_endpoints(hd, param_urls, scope_text)

summary = {
    "phase": "06-param-discovery",
    "domain": hd.name,
    "tools_run": tools_run or ["querystring-parse"],
    "tools_skipped": tools_skipped,
    "count": len(items),
    "unique_params": sorted({i["param"] for i in items})[:100],
    "items": cap_items(items),
    "notes": [
        "Each item is a (url, param) pair. These feed recon-15 one-liners.",
        "Not findings — parameters are attack surface.",
    ],
    "output_files": [str(out / "param_urls.txt")],
}
write_json(out / "summary.json", summary)
print(json.dumps({"phase": "06", "count": len(items), "param_urls": len(param_urls)}))
PY

mark_done "$domain" "recon-06"
