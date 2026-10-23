#!/usr/bin/env bash
# Phase 08 — technology fingerprint from HTTP headers / titles / whatweb.
# Version matches are the input to skill version_match hypotheses.
set -euo pipefail
source "$(dirname "$0")/_common.sh"
domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/08-tech-fingerprint"
script_dir="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$out"

python3 - "$out" "$hd" "$script_dir" <<'PY'
import json, re, shutil, subprocess, sys
from pathlib import Path

sys.path.insert(0, sys.argv[3])
from _recon_io import live_urls, cap_items, write_json, read_json

out, hd = Path(sys.argv[1]), Path(sys.argv[2])
tools_run, tools_skipped = ["header-parse"], []
items = []

HINTS = [
    (re.compile(r"wordpress|wp-json|wp-content", re.I), "wordpress", "seeds/wordpress"),
    (re.compile(r"struts|org\.apache\.struts|\.action\b", re.I), "apache-struts", "seeds/apache-struts"),
    (re.compile(r"graphql", re.I), "graphql", "seeds/graphql"),
    (re.compile(r"jwt|json web token", re.I), "jwt", "seeds/jwt"),
    (re.compile(r"nginx", re.I), "nginx", None),
    (re.compile(r"apache(?:/(\d[\d.]+))?", re.I), "apache", None),
    (re.compile(r"iis|microsoft-httpapi|asp\.net", re.I), "iis/aspnet", None),
    (re.compile(r"jetty", re.I), "jetty", None),
    (re.compile(r"vaadin", re.I), "vaadin", None),
    (re.compile(r"spring|whitelabel error", re.I), "spring", None),
    (re.compile(r"django", re.I), "django", None),
    (re.compile(r"express|x-powered-by:\s*express", re.I), "express", None),
    (re.compile(r"php(?:/(\d[\d.]+))?", re.I), "php", None),
    (re.compile(r"oauth|openid", re.I), "oauth/oidc", "seeds/oauth"),
]

blob_parts = []
http = read_json(hd / "recon" / "04-http-probe" / "http.json", {})
if isinstance(http, dict):
    blob_parts.append(json.dumps(http))
    for host, rows in http.items():
        for row in rows if isinstance(rows, list) else [rows]:
            if not isinstance(row, dict):
                continue
            text = " ".join(str(v) for v in row.values())
            for rx, tech, skill in HINTS:
                if rx.search(text):
                    items.append({
                        "host": host,
                        "url": row.get("url", ""),
                        "tech": tech,
                        "evidence": text[:240],
                        "skill_hint": skill,
                    })

# whatweb optional
if shutil.which("whatweb") and live_urls(hd):
    tools_run.append("whatweb")
    ww = out / "whatweb.txt"
    try:
        subprocess.run(
            ["whatweb", "-a", "1", "--log-brief", str(ww), *live_urls(hd)[:15]],
            timeout=90,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    if ww.is_file():
        blob_parts.append(ww.read_text(errors="ignore")[:50_000])
else:
    tools_skipped.append({"tool": "whatweb", "reason": "not installed; headers/titles used"})

# Dedup by host+tech
uniq, seen = [], set()
for i in items:
    k = (i.get("host"), i.get("tech"))
    if k in seen:
        continue
    seen.add(k)
    uniq.append(i)

summary = {
    "phase": "08-tech-fingerprint",
    "domain": hd.name,
    "tools_run": tools_run,
    "tools_skipped": tools_skipped,
    "count": len(uniq),
    "items": cap_items(uniq),
    "notes": [
        "skill_hint is a suggested checklist, not a CVE confirmation.",
        "Use version_match only when a version string is present in evidence.",
    ],
    "output_files": [],
}
write_json(out / "summary.json", summary)
print(json.dumps({"phase": "08", "count": len(uniq)}))
PY

mark_done "$domain" "recon-08"
