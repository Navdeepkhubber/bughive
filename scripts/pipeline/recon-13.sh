#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"
domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/13-secret-scan"
cache="$hd/recon/12-response-cache"
mkdir -p "$out"

tools_run=()
tools_skipped=()
count=0
items_file="$out/items.jsonl"
: > "$items_file"

if [ ! -d "$cache" ]; then
  echo '{"phase":"13-secret-scan","domain":"'"$domain"'","tools_run":[],"tools_skipped":[{"tool":"all","reason":"no response cache (phase 12) found"}],"count":0,"items":[],"notes":[],"output_files":[]}' > "$out/summary.json"
  mark_done "$domain" "recon-13"; echo '{"phase":"13","count":0}'; exit 0
fi

run_scanner() {
  local name="$1"; shift
  if command -v "$name" >/dev/null 2>&1; then
    tools_run+=("$name")
    timeout 180 "$@" > "$out/${name}.raw" 2>/dev/null || true
  else
    tools_skipped+=("{\"tool\":\"$name\",\"reason\":\"not installed\"}")
  fi
}

run_scanner trufflehog trufflehog filesystem "$cache"
run_scanner gitleaks gitleaks detect --source "$cache" --no-git --report-format json --report-path "$out/gitleaks.raw"
run_scanner kingfisher kingfisher scan "$cache"

# Custom regex pass -- always runs, no external dependency beyond ripgrep/grep.
if command -v rg >/dev/null 2>&1; then
  tools_run+=("rg")
  timeout 60 rg -n --hidden -i \
    'Basic[[:space:]]+([A-Za-z0-9_=\+/-]{10,})|Bearer[[:space:]]+([A-Za-z0-9._~+/-]{20,})' \
    "$cache" > "$out/rg-auth-headers.raw" 2>/dev/null || true
  timeout 30 rg -n -o 'AIza[0-9A-Za-z_-]{35}' "$cache" > "$out/google-api-keys.raw" 2>/dev/null || true
else
  tools_skipped+=('{"tool":"rg","reason":"ripgrep not installed"}')
fi

count=$(cat "$out"/*.raw 2>/dev/null | grep -c . || true)
tools_run_json=""
[ "${#tools_run[@]}" -gt 0 ] && tools_run_json=$(printf '"%s",' "${tools_run[@]}" | sed 's/,$//')
tools_skipped_json=""
[ "${#tools_skipped[@]}" -gt 0 ] && tools_skipped_json=$(printf '%s,' "${tools_skipped[@]}" | sed 's/,$//')

cat > "$out/summary.json" <<EOF
{"phase":"13-secret-scan","domain":"$domain","tools_run":[$tools_run_json],"tools_skipped":[$tools_skipped_json],"count":$count,"items":[],"notes":["raw scanner output under $out; values are NOT redacted in the raw files -- only summary.json is safe to embed in prompts, and even that carries no items here until a human/agent redacts and populates them from the raw output"],"output_files":["$out"]}
EOF

mark_done "$domain" "recon-13"
echo '{"phase":"13","count":'"$count"'}'
