#!/usr/bin/env bash
# Phase 10 — cloud / takeover-shaped assets from DNS CNAMEs and URLs.
# Records candidates only. Serving content on a dangling CNAME is still a
# manual proof (subdomain-takeover is not payload-validatable).
set -euo pipefail
source "$(dirname "$0")/_common.sh"
domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/10-cloud-assets"
script_dir="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$out"

python3 - "$out" "$hd" "$script_dir" <<'PY'
import json, re, sys
from pathlib import Path

sys.path.insert(0, sys.argv[3])
from _recon_io import read_json, write_json, cap_items

out, hd = Path(sys.argv[1]), Path(sys.argv[2])

FINGERPRINTS = [
    (re.compile(r"s3\.amazonaws\.com|s3[\w.-]*\.amazonaws\.com", re.I), "s3"),
    (re.compile(r"cloudfront\.net", re.I), "cloudfront"),
    (re.compile(r"azurewebsites\.net|blob\.core\.windows\.net", re.I), "azure"),
    (re.compile(r"googleapis\.com|storage\.googleapis\.com|appspot\.com", re.I), "gcp"),
    (re.compile(r"herokuapp\.com", re.I), "heroku"),
    (re.compile(r"github\.io", re.I), "github-pages"),
    (re.compile(r"firebaseio\.com|web\.app", re.I), "firebase"),
    (re.compile(r"cloudapp\.azure\.com", re.I), "azure-cloudapp"),
    (re.compile(r"amazonaws\.com", re.I), "aws"),
    (re.compile(r"fastly\.net", re.I), "fastly"),
    (re.compile(r"zendesk\.com|freshdesk\.com|shopify\.com|unbouncepages\.com|ghost\.io", re.I), "saas-cname"),
]

items = []
dns = read_json(hd / "recon" / "02-dns-resolution" / "summary.json", {})
results = dns.get("records") or read_json(hd / "recon" / "02-dns-resolution" / "dns-records.json", {})
if isinstance(results, dict):
    for host, rec in results.items():
        if not isinstance(rec, dict):
            continue
        for rtype in ("CNAME", "A", "AAAA", "MX", "NS", "TXT"):
            for val in rec.get(rtype) or []:
                text = str(val)
                for rx, kind in FINGERPRINTS:
                    if rx.search(text):
                        items.append({"host": host, "record": rtype, "value": text, "kind": kind, "source": "dns"})

# URLs
ep = hd / "recon" / "all_endpoints"
if ep.is_file():
    for line in ep.read_text().splitlines()[:4000]:
        for rx, kind in FINGERPRINTS:
            if rx.search(line):
                items.append({"url": line.strip(), "kind": kind, "source": "url"})
                break

uniq, seen = [], set()
for i in items:
    k = (i.get("host") or i.get("url"), i.get("kind"), i.get("value") or "")
    if k in seen:
        continue
    seen.add(k)
    uniq.append(i)

summary = {
    "phase": "10-cloud-assets",
    "domain": hd.name,
    "tools_run": ["dns-parse", "url-parse"],
    "tools_skipped": [],
    "count": len(uniq),
    "items": cap_items(uniq),
    "notes": [
        "Cloud/CNAME fingerprints are leads for seeds/subdomain-takeover and cloud misconfig.",
        "A CNAME match is not a takeover. Confirm the claimed service is unclaimed before reporting.",
    ],
    "output_files": [],
}
write_json(out / "summary.json", summary)
print(json.dumps({"phase": "10", "count": len(uniq)}))
PY

mark_done "$domain" "recon-10"
