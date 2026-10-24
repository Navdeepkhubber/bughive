#!/usr/bin/env bash
# Phase 07 — JS/HTML security analysis.
#
# Previously a stub (count always 0), which meant the pipeline collected JS bundles and
# never looked inside them. This now:
#   1. collects JS/HTML asset URLs discovered by earlier phases,
#   2. downloads a BOUNDED, rate-limited sample into assets/ (skipped if already present),
#   3. runs the shared dsh-js-analyzer rule engine over everything on disk.
#
# Leads (client-side redirect allowlists, client-side authz, DOM XSS sinks, postMessage
# handlers, secrets, debug flags, internal hosts, graphql, jwt handling) land in
# items.jsonl with a suggested next request. Endpoints land in endpoints.txt.
#
# Network use is bounded and non-destructive: GET only, hard file cap, per-request timeout.
set -euo pipefail
source "$(dirname "$0")/_common.sh"
domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/07-js-analysis"
assets="$out/assets"
mkdir -p "$out" "$assets"

script_dir="$(cd "$(dirname "$0")" && pwd)"
eval "$(python3 "$script_dir/_batch.py" exports)"
# BH_JS_MAX_ASSETS remains an explicit override. 0 means "no global total":
# the per-host cap and the wall clock are the bounds.
if [ -n "${BH_JS_MAX_ASSETS:-}" ]; then
  MAX_ASSETS="$BH_JS_MAX_ASSETS"
else
  MAX_ASSETS="${BUGHIVE_JS_FETCH_TOTAL:-0}"
fi
PER_HOST="${BUGHIVE_JS_FETCH_CAP:-50}"
JS_BUDGET="${BUGHIVE_JS_BUDGET_SECONDS:-300}"

# ---------------------------------------------------------------- asset URLs
# Normalize to https, strip :80/:443, collapse duplicated slashes, and keep
# only hosts that scope.txt already allows. Sibling properties and CDN file
# hosts (p-airnz.com, flightbookings.…) stay out.
urls="$out/asset_urls.txt"
fetch="$out/asset_fetch.tsv"
: > "$urls"
raw_urls="$out/asset_urls.raw.txt"
: > "$raw_urls"
for f in "$hd/recon/all_endpoints" \
         "$hd/recon/04-http-probe/urls.txt" \
         "$hd/recon/04-http-probe/httpx.txt" \
         "$hd/recon/05-content-discovery/items.jsonl" \
         "$hd/recon/17-interesting-endpoints/items.jsonl"; do
  [ -f "$f" ] || continue
  grep -oiE 'https?://[^"'"'"' <>]+\.(js|mjs|html?)(\?[^"'"'"' <>]*)?' "$f" >> "$raw_urls" 2>/dev/null || true
done
python3 - "$raw_urls" "$urls" "$fetch" "$hd/scope.txt" "$out/asset_filter.json" "$script_dir" <<'PY'
import json, sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, sys.argv[6])
from _recon_safety import asset_filename, normalize_asset_url
from _scope import scope_allows

raw_path, urls_path, fetch_path, scope_path, meta_path = map(Path, sys.argv[1:6])
scope_text = scope_path.read_text() if scope_path.is_file() else ""
seen = []
dropped = 0
for line in raw_path.read_text(errors="ignore").splitlines():
    norm = normalize_asset_url(line.strip())
    if not norm or norm in seen:
        continue
    if not scope_text:
        dropped += 1
        continue
    host = urlsplit(norm).hostname or ""
    ok, _reason = scope_allows(scope_text, host)
    if not ok:
        dropped += 1
        continue
    seen.append(norm)
urls_path.write_text("".join(f"{u}\n" for u in seen))
lines = []
for url in seen:
    name = asset_filename(url)
    if "/" in name or name.startswith("."):
        continue
    lines.append(f"{url}\t{name}\n")
fetch_path.write_text("".join(lines))
meta_path.write_text(json.dumps({
    "urls_in_scope": len(seen),
    "urls_dropped": dropped,
}, indent=2) + "\n")
PY
rm -f "$raw_urls"

# ---------------------------------------------------------------- download (bounded)
# Cap each host, then the optional global total, before any GET. The loop
# also stops when the wall clock expires and records a truncated marker.
python3 - "$fetch" "$PER_HOST" "$MAX_ASSETS" <<'PY'
import sys
from pathlib import Path
from urllib.parse import urlsplit
path, per_host, total = Path(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
rows = []
seen_host = {}
for line in path.read_text(errors="ignore").splitlines() if path.is_file() else []:
    url, _, name = line.partition("\t")
    url, name = url.strip(), name.strip()
    if not url or not name:
        continue
    host = (urlsplit(url).hostname or "").lower()
    seen_host[host] = seen_host.get(host, 0) + 1
    if seen_host[host] > per_host:
        continue
    rows.append(f"{url}\t{name}")
    if total > 0 and len(rows) >= total:
        break
dropped = 0
if path.is_file():
    raw = [l for l in path.read_text(errors="ignore").splitlines() if l.strip()]
    dropped = max(0, len(raw) - len(rows))
path.write_text("".join(f"{row}\n" for row in rows))
marker = path.with_name(".js-fetch-capped")
marker.write_text("1\n" if dropped else "0\n")
PY
downloaded=0
js_truncated=0
effective="$out/asset_effective.tsv"
: > "$effective"
js_deadline=$(( $(date +%s) + JS_BUDGET ))
if [ ! -d "$assets" ] || [ -z "$(ls -A "$assets" 2>/dev/null || true)" ]; then
  if [ -s "$fetch" ]; then
    while IFS=$'\t' read -r u name; do
      [ -n "$u" ] || continue
      [ -n "$name" ] || continue
      if [ "$(date +%s)" -ge "$js_deadline" ]; then
        js_truncated=1
        break
      fi
      if [ "$MAX_ASSETS" -gt 0 ] && [ "$downloaded" -ge "$MAX_ASSETS" ]; then
        js_truncated=1
        break
      fi
      case "$name" in
        *[!a-zA-Z0-9._-]*|.*|*/*) continue ;;
      esac
      # -L follows the http:80 -> https upgrade. The final host is checked
      # below so a redirect onto an out-of-scope property is not kept.
      final="$(curl -sSL --compressed --max-time 15 -A "bh-recon/0.1 (authorized; non-destructive)" \
           -o "$assets/$name" -w '%{url_effective}' "$u" 2>/dev/null || true)"
      printf '%s\t%s\n' "$name" "$final" >> "$effective"
      downloaded=$((downloaded + 1))
      sleep 0.3   # stay polite: never turn recon into a flood
    done < "$fetch"
  fi
fi
if [ -s "$effective" ]; then
  python3 - "$effective" "$assets" "$hd/scope.txt" "$script_dir" <<'PY'
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, sys.argv[4])
from _scope import scope_allows

rows = Path(sys.argv[1]).read_text(errors="ignore").splitlines()
assets = Path(sys.argv[2])
scope_path = Path(sys.argv[3])
scope_text = scope_path.read_text() if scope_path.is_file() else ""
for line in rows:
    name, _, final = line.partition("\t")
    name = name.strip()
    if not name or "/" in name or name.startswith("."):
        continue
    host = (urlsplit(final.strip()).hostname or "") if final.strip() else ""
    ok = bool(host) and bool(scope_text) and scope_allows(scope_text, host)[0]
    if not ok:
        target = assets / name
        if target.is_file():
            target.unlink()
PY
fi

# ---------------------------------------------------------------- analyse
scan_count=$(find "$assets" -type f 2>/dev/null | wc -l | tr -d ' ')
if [ "$scan_count" -eq 0 ]; then
  # Nothing fetched: still scan any assets other phases left behind in recon/.
  node "$WS_ROOT/plugins/dsh-js-analyzer/cli.mjs" "$hd/recon" --out "$out" >/dev/null
else
  node "$WS_ROOT/plugins/dsh-js-analyzer/cli.mjs" "$assets" --out "$out" >/dev/null
fi

# ---------------------------------------------------------------- phase contract
count=$(python3 -c "
import json
try:
    print(json.load(open('$out/summary.json')).get('count', 0))
except Exception:
    print(0)
")
python3 - "$out/summary.json" "$domain" "$scan_count" "$downloaded" "$js_truncated" "$out/.js-fetch-capped" <<'PY'
import json, os, sys
path, domain, scanned, downloaded = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
timed_out = sys.argv[5] == "1"
try:
    capped = open(sys.argv[6]).read().strip() == "1"
except OSError:
    capped = False
truncated = timed_out or capped
try:
    s = json.load(open(path))
except Exception:
    s = {}
s["domain"] = domain
s["assets_downloaded"] = downloaded
s["assets_on_disk"] = scanned
s["truncated"] = bool(truncated or s.get("truncated"))
if truncated:
    s["degraded"] = True
    notes = list(s.get("notes") or [])
    notes.append("JS fetch hit the per-host cap or the wall-clock budget; partial assets kept")
    s["notes"] = notes
meta_path = os.path.join(os.path.dirname(path), "asset_filter.json")
try:
    meta = json.load(open(meta_path))
except Exception:
    meta = {}
if meta:
    s["urls_in_scope"] = meta.get("urls_in_scope", 0)
    s["urls_dropped"] = meta.get("urls_dropped", 0)
json.dump(s, open(path, "w"), indent=2)
PY

mark_done "$domain" "recon-07"
echo '{"phase":"07","count":'"$count"'}'
