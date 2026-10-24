#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"
domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/15-mass-oneliners"
cache="$hd/recon/12-response-cache"
endpoints="$hd/recon/all_endpoints"
mkdir -p "$out"
# Drop a previous run's SSRF file. Only a non-empty oob-hits poll may recreate it.
rm -f "$out/vuln-ssrf"

tools_run=()
tools_skipped=()
count=0

have_qsreplace=0; command -v qsreplace >/dev/null 2>&1 && have_qsreplace=1
have_httpx=0; command -v httpx >/dev/null 2>&1 && have_httpx=1

param_urls="$out/param_urls.txt"
if [ -f "$endpoints" ]; then
  grep "=" "$endpoints" > "$param_urls" 2>/dev/null || : > "$param_urls"
else
  : > "$param_urls"
fi

# Prefer param_urls from phase 06 when all_endpoints has no query strings yet.
if [ ! -s "$param_urls" ] && [ -f "$hd/recon/06-param-discovery/param_urls.txt" ]; then
  cp "$hd/recon/06-param-discovery/param_urls.txt" "$param_urls"
fi
if [ ! -s "$param_urls" ] && [ -f "$hd/recon/09-historical-data/param_urls.txt" ]; then
  cat "$hd/recon/09-historical-data/param_urls.txt" >> "$param_urls" || true
  sort -u -o "$param_urls" "$param_urls"
fi

if [ "$have_qsreplace" -eq 1 ] && [ "$have_httpx" -eq 1 ]; then
  tools_run+=("qsreplace" "httpx")

  # XSS
  timeout 300 bash -c "cat '$param_urls' | qsreplace '\"><bughive-xss-marker>' | httpx -ms '<bughive-xss-marker>' -silent -o '$out/vuln-xss'" 2>/dev/null || true

  # SSRF / blind classes need an out-of-band collaborator. Previously this phase simply
  # skipped them when BUGHIVE_COLLABORATOR_URL was unset, so blind SSRF/XXE/JNDI were
  # structurally untestable. Now it starts the local OOB listener automatically.
  #
  # REACH: a loopback listener is only reachable by a target that can route to this host
  # (local/CI fixtures, or a target on the same network). For a REMOTE target you must run
  # the listener behind a tunnel and set BUGHIVE_COLLABORATOR_URL to that public URL --
  # otherwise no callback can arrive and the absence of a hit proves nothing.
  repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
  oob_cli="$repo_root/plugins/dsh-oob/oob-cli.mjs"
  oob_log="$out/oob.jsonl"
  oob_port=8787
  oob_pid=""
  cleanup_oob() { [ -n "$oob_pid" ] && kill "$oob_pid" 2>/dev/null || true; }
  trap cleanup_oob EXIT

  collab="${BUGHIVE_COLLABORATOR_URL:-}"
  if [ -z "$collab" ] && command -v node >/dev/null 2>&1 && [ -f "$oob_cli" ]; then
    node "$oob_cli" serve --port "$oob_port" --log "$oob_log" >/dev/null 2>&1 &
    oob_pid=$!
    sleep 1
    collab="$(node "$oob_cli" tokens --port "$oob_port" --log "$oob_log" 2>/dev/null \
      | python3 -c "import json,sys; print(json.load(sys.stdin).get('url',''))" 2>/dev/null || echo '')"
    if [ -n "$collab" ]; then
      tools_run+=("oob-local")
      log "local OOB collaborator: $collab (loopback reach only)"
    fi
  fi

  # httpx -fr records the payloaded requests that were SENT, not OOB callbacks.
  # A stale vuln-ssrf from an earlier run must not be promoted either.
  rm -f "$out/vuln-ssrf"
  if [ -n "$collab" ]; then
    mkdir -p "$out/provenance"
    timeout 300 bash -c "cat '$param_urls' | qsreplace '$collab' | httpx -fr -silent -o '$out/provenance/ssrf-sent.txt'" 2>/dev/null || true
    : > "$out/oob-hits"
    if [ -f "$oob_log" ]; then
      node "$oob_cli" poll --log "$oob_log" --format urls > "$out/oob-hits" 2>/dev/null || true
    fi
    # One integer. grep -c already prints 0 when nothing matches; do not
    # append another 0, or the value becomes two lines and the test breaks.
    hits=$(line_count "$out/oob-hits")
    hits="${hits%%$'\n'*}"
    case "$hits" in
      ''|*[!0-9]*) hits=0 ;;
    esac
    if [ "$hits" -gt 0 ]; then
      log "OOB: $hits out-of-band interaction(s) recorded — see $out/oob-hits"
      cp "$out/oob-hits" "$out/vuln-ssrf"
      printf 'status=confirmed\nhits=%s\nsent_payloads=provenance/ssrf-sent.txt\n' "$hits" > "$out/ssrf-status.txt"
    else
      printf 'status=unconfirmed\nhits=0\nsent_payloads=provenance/ssrf-sent.txt\n' > "$out/ssrf-status.txt"
      log "SSRF probes sent; no OOB interaction recorded (not promoted)"
    fi
    cleanup_oob
    oob_pid=""
  else
    printf 'status=skipped\nhits=0\n' > "$out/ssrf-status.txt"
    tools_skipped+=('{"tool":"ssrf-check","reason":"no collaborator available: node or oob-cli missing and BUGHIVE_COLLABORATOR_URL unset. Blind SSRF/XXE/JNDI were NOT tested."}')
  fi

  # SSTI
  timeout 300 bash -c "cat '$param_urls' | qsreplace '{{4327*8191}}' | httpx -ms '35442497' -silent -o '$out/vuln-ssti'" 2>/dev/null || true
else
  [ "$have_qsreplace" -eq 1 ] || tools_skipped+=('{"tool":"qsreplace","reason":"not installed; python GET fallback used"}')
  [ "$have_httpx" -eq 1 ] || tools_skipped+=('{"tool":"httpx","reason":"not installed; python GET fallback used"}')
  python3 - "$param_urls" "$out" <<'PY'
import sys, time
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

param_file, out = Path(sys.argv[1]), Path(sys.argv[2])
urls = [l.strip() for l in param_file.read_text().splitlines() if l.strip() and "=" in l][:80]
xss_hits, ssti_hits = [], []
XSS = '"><bughive-xss-marker>'
SSTI = "{{4327*8191}}"
SSTI_OUT = "35442497"

def mutate(url, payload):
    parts = urlsplit(url)
    q = [(k, payload) for k, _ in parse_qsl(parts.query, keep_blank_values=True)]
    if not q:
        return None
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q, safe=""), parts.fragment))

def fetch(url):
    req = Request(url, headers={"User-Agent": "bh-recon/0.1 (authorized; non-destructive)"})
    try:
        with urlopen(req, timeout=10) as resp:
            return resp.read(200_000).decode("utf-8", "replace")
    except Exception:
        return ""

for u in urls:
    xu = mutate(u, XSS)
    if xu:
        body = fetch(xu)
        if "bughive-xss-marker" in body:
            xss_hits.append(xu)
        time.sleep(0.15)
    su = mutate(u, SSTI)
    if su:
        body = fetch(su)
        if SSTI_OUT in body:
            ssti_hits.append(su)
        time.sleep(0.15)

(out / "vuln-xss").write_text("".join(f"{h}\n" for h in xss_hits))
(out / "vuln-ssti").write_text("".join(f"{h}\n" for h in ssti_hits))
PY
  tools_run+=("python-param-probe")
fi

# CORS check -- pure grep, no external tool dependency beyond the phase-12 cache existing.
if [ -d "$cache" ]; then
  tools_run+=("grep")
  find "$cache" -name '*.headers' -type f -exec grep -l "Access-Control-Allow-Credentials: true" {} + > "$out/vuln-cors-candidates" 2>/dev/null || : > "$out/vuln-cors-candidates"
else
  tools_skipped+=('{"tool":"cors-check","reason":"no response cache (phase 12) found"}')
fi

for f in "$out"/vuln-xss "$out"/vuln-ssrf "$out"/vuln-ssti "$out"/vuln-cors-candidates; do
  [ -f "$f" ] && count=$((count + $(grep -c . "$f" 2>/dev/null || true)))
done

python3 - "$out" "$domain" "$count" <<'PY'
import json, sys
from pathlib import Path
out, domain, count = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
mapping = {
    "vuln-xss": ("seeds/xss", "xss"),
    "vuln-ssrf": ("seeds/ssrf", "ssrf"),
    "vuln-ssti": ("seeds/xss", "ssti"),
    "vuln-cors-candidates": ("seeds/unauth-api", "cors"),
}
items = []
for name, (skill, bug) in mapping.items():
    p = out / name
    if not p.is_file():
        continue
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        items.append({"url": line, "skill": skill, "bugClass": bug, "source": name, "priority": 9})
summary_path = out / "summary.json"
# Preserve tools_* if the shell already wrote them — we rewrite fully here.
# The shell passes tools via sibling files if present.
run, skipped = [], []
tr, ts = out / ".tools-run", out / ".tools-skipped"
if tr.is_file():
    run = [l.strip() for l in tr.read_text().splitlines() if l.strip()]
if ts.is_file():
    import json as _j
    for l in ts.read_text().splitlines():
        try:
            skipped.append(_j.loads(l))
        except Exception:
            pass
# If empty, leave empty — bash will have printed tools into env only.
summary = {
    "phase": "15-mass-oneliners",
    "domain": domain,
    "tools_run": run,
    "tools_skipped": skipped,
    "count": count,
    "items": items[:200],
    "notes": [
        "Hits are candidates, not findings. SSTI product 35442497 in the body is a strong lead.",
        "XSS marker reflection is NOT XSS until a matcher confirms it on a saved response.",
        "A count of 0 means no parameter URL was probed or no marker matched. It is not a clean bill of health.",
        "SSRF priority-9 rows are OOB interactions from oob-hits. httpx -fr requests that were only sent live in provenance/ssrf-sent.txt and are not candidates.",
    ],
    "output_files": [str(out)],
}
(out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps({"phase": "15", "count": count, "items": len(items)}))
PY

# tools arrays: write sidecars so the python summary can include them
: > "$out/.tools-run"
for t in "${tools_run[@]+"${tools_run[@]}"}"; do printf '%s\n' "$t" >> "$out/.tools-run"; done
: > "$out/.tools-skipped"
for t in "${tools_skipped[@]+"${tools_skipped[@]}"}"; do printf '%s\n' "$t" >> "$out/.tools-skipped"; done
# Re-run summary merge now that sidecars exist
python3 - "$out" "$domain" "$count" <<'PY'
import json, sys
from pathlib import Path
out, domain, count = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
summary = json.loads((out / "summary.json").read_text())
run = [l.strip() for l in (out / ".tools-run").read_text().splitlines() if l.strip()] if (out / ".tools-run").is_file() else []
skipped = []
if (out / ".tools-skipped").is_file():
    for l in (out / ".tools-skipped").read_text().splitlines():
        l = l.strip()
        if not l:
            continue
        try:
            skipped.append(json.loads(l))
        except Exception:
            skipped.append({"tool": l, "reason": "unknown"})
summary["tools_run"] = run
summary["tools_skipped"] = skipped
summary["domain"] = domain
summary["count"] = count
(out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
PY

mark_done "$domain" "recon-15"
echo '{"phase":"15","count":'"$count"'}'
