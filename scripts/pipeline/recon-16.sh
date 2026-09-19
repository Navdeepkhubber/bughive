#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"
domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/16-github-dorking"
mkdir -p "$out"

if command -v GitDorker.py >/dev/null 2>&1 || command -v gitdorker >/dev/null 2>&1; then
  bin=$(command -v gitdorker.py || command -v GitDorker.py || command -v gitdorker)
  if [ -z "${GITHUB_TOKEN:-}" ]; then
    echo '{"phase":"16-github-dorking","domain":"'"$domain"'","tools_run":[],"tools_skipped":[{"tool":"gitdorker","reason":"GITHUB_TOKEN not set; skipping rather than hammering the unauthenticated rate limit"}],"count":0,"items":[],"notes":[],"output_files":[]}' > "$out/summary.json"
  else
    log "GitDorker for $domain"
    timeout 900 python3 "$bin" -d "$domain" -token "$GITHUB_TOKEN" -o "$out/github_output" 2>/dev/null || true
    count=0
    [ -f "$out/github_output" ] && count=$(grep -c . "$out/github_output" 2>/dev/null || true)
    cat > "$out/summary.json" <<EOF
{"phase":"16-github-dorking","domain":"$domain","tools_run":["gitdorker"],"tools_skipped":[],"count":$count,"items":[],"notes":["raw output under $out/github_output; redact before embedding any snippet in a prompt"],"output_files":["$out/github_output"]}
EOF
  fi
else
  echo '{"phase":"16-github-dorking","domain":"'"$domain"'","tools_run":[],"tools_skipped":[{"tool":"gitdorker","reason":"not installed -- see skills/seeds/github-recon.md for the manual dork list to run by hand instead"}],"count":0,"items":[],"notes":[],"output_files":[]}' > "$out/summary.json"
fi

mark_done "$domain" "recon-16"
echo '{"phase":"16"}'
