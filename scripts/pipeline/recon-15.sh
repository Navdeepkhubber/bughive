#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"
domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/15-mass-oneliners"
cache="$hd/recon/12-response-cache"
endpoints="$hd/recon/all_endpoints"
mkdir -p "$out"

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

  if [ -n "$collab" ]; then
    timeout 300 bash -c "cat '$param_urls' | qsreplace '$collab' | httpx -fr -silent -o '$out/vuln-ssrf'" 2>/dev/null || true
    # Correlate any interaction back to the payload.
    if [ -f "$oob_log" ]; then
      node "$oob_cli" poll --log "$oob_log" --format urls > "$out/oob-hits" 2>/dev/null || true
      hits=$(grep -c . "$out/oob-hits" 2>/dev/null || echo 0)
      [ "$hits" -gt 0 ] && log "OOB: $hits out-of-band interaction(s) recorded — see $out/oob-hits"
    fi
    cleanup_oob
    oob_pid=""
  else
    tools_skipped+=('{"tool":"ssrf-check","reason":"no collaborator available: node or oob-cli missing and BUGHIVE_COLLABORATOR_URL unset. Blind SSRF/XXE/JNDI were NOT tested."}')
  fi

  # SSTI
  timeout 300 bash -c "cat '$param_urls' | qsreplace '{{4327*8191}}' | httpx -ms '35442497' -silent -o '$out/vuln-ssti'" 2>/dev/null || true
else
  [ "$have_qsreplace" -eq 1 ] || tools_skipped+=('{"tool":"qsreplace","reason":"not installed"}')
  [ "$have_httpx" -eq 1 ] || tools_skipped+=('{"tool":"httpx","reason":"not installed"}')
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

tools_run_json=""
[ "${#tools_run[@]}" -gt 0 ] && tools_run_json=$(printf '"%s",' "${tools_run[@]}" | sed 's/,$//')
tools_skipped_json=""
[ "${#tools_skipped[@]}" -gt 0 ] && tools_skipped_json=$(printf '%s,' "${tools_skipped[@]}" | sed 's/,$//')

cat > "$out/summary.json" <<EOF
{"phase":"15-mass-oneliners","domain":"$domain","tools_run":[$tools_run_json],"tools_skipped":[$tools_skipped_json],"count":$count,"items":[],"notes":["raw hit files (vuln-xss, vuln-ssrf, vuln-ssti, vuln-cors-candidates) under $out; each hit is a candidate for the falsifier stage, not yet a confirmed finding"],"output_files":["$out"]}
EOF

mark_done "$domain" "recon-15"
echo '{"phase":"15","count":'"$count"'}'
