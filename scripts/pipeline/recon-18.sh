#!/usr/bin/env bash
# Phase 18 — source-code audit (white-box).
#
# XBOW's zero-day work gave the model SOURCE CODE; white-box consistently outperforms
# black-box on the published benchmarks (Shannon 96% white-box). This repo had no source
# phase at all: the Threema engagement had complete open-source clients available and used
# them only to read protocol facts, never to look for bugs.
#
# Operator supplies a checkout at:
#     hunts/<domain>/source/            (git clone, unzipped tarball, vendor SDK...)
#
# Then:
#   1. semgrep, if installed, with the security-audit + owasp rulesets (JSON parsed).
#   2. Otherwise a built-in multi-language pattern pass so the phase is never a no-op,
#      reusing the JS rule engine for JS/TS/HTML and grep patterns for the other languages.
#
# Output: items.jsonl (each hit = a lead with file:line), summary.json.
set -euo pipefail
source "$(dirname "$0")/_common.sh"

domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/18-source-audit"
src="$hd/source"
mkdir -p "$out"

# Auto-clone when a repo URL was supplied, so white-box audit is one step rather than a
# manual prerequisite nobody performs. Sources, in order of precedence:
#   hunts/<domain>/source-url.txt   (one URL)
#   BUGHIVE_SOURCE_REPO             (environment)
if [ ! -d "$src" ]; then
  repo_url=""
  if [ -f "$hd/source-url.txt" ]; then
    repo_url="$(head -1 "$hd/source-url.txt" | tr -d '[:space:]')"
  fi
  [ -z "$repo_url" ] && repo_url="${BUGHIVE_SOURCE_REPO:-}"
  if [ -n "$repo_url" ] && command -v git >/dev/null 2>&1; then
    log "auto-cloning source for audit: $repo_url"
    if timeout 900 git clone --depth 1 "$repo_url" "$src" >/dev/null 2>&1; then
      log "cloned into $src"
    else
      log "clone failed (network/private repo?); continuing without source"
      rm -rf "$src"
    fi
  fi
fi

if [ ! -d "$src" ]; then
  cat > "$out/summary.json" <<EOF
{"phase":"18-source-audit","domain":"$domain","degraded":true,"count":0,"items":[],"tools_run":[],"tools_skipped":[{"tool":"semgrep","reason":"no source checkout at hunts/$domain/source/"}],"notes":["SKIPPED: white-box audit requires a source checkout. Place one at hunts/$domain/source/ (git clone, tarball, or vendor SDK) and re-run: bash scripts/pipeline/run.sh recon-18 $domain"],"output_files":[]}
EOF
  mark_done "$domain" "recon-18"
  echo '{"phase":"18","count":0,"degraded":true}'
  exit 0
fi

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
js_cli="$repo_root/plugins/dsh-js-analyzer/cli.mjs"
items="$out/items.jsonl"
: > "$items"
tools_run=()
tools_skipped=()

# ------------------------------------------------------------------ semgrep
if command -v semgrep >/dev/null 2>&1; then
  tools_run+=("semgrep")
  timeout 600 semgrep --config=p/security-audit --config=p/owasp-top-ten \
    --json --quiet --max-target-bytes 2000000 "$src" > "$out/semgrep.json" 2>/dev/null || true
  if [ -s "$out/semgrep.json" ]; then
    python3 - "$out/semgrep.json" "$items" <<'PY' || true
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
out = open(sys.argv[2], "a")
for r in data.get("results", []):
    extra = r.get("extra", {}) or {}
    out.write(json.dumps({
        "tool": "semgrep",
        "rule": r.get("check_id", ""),
        "severity": (extra.get("severity") or "unknown").lower(),
        "file": r.get("path", ""),
        "line": (r.get("start") or {}).get("line"),
        "message": (extra.get("message") or "")[:300],
    }) + "\n")
PY
  fi
else
  tools_skipped+=('{"tool":"semgrep","reason":"not installed; used the built-in pattern pass instead"}')
fi

# ------------------------------------------- built-in multi-language pattern pass
tools_run+=("patterns")

# JS/TS/HTML via the shared rule engine (redirect allowlists, DOM sinks, secrets...).
if command -v node >/dev/null 2>&1 && [ -f "$js_cli" ]; then
  node "$js_cli" "$src" --out "$out" >/dev/null 2>&1 || true
  if [ -f "$out/items.jsonl" ] && [ -s "$out/items.jsonl" ]; then
    python3 - "$out/items.jsonl" "$items" <<'PY' || true
import json, sys
seen = set()
src = open(sys.argv[1]); dst = open(sys.argv[2], "a")
for line in src:
    line = line.strip()
    if not line:
        continue
    try:
        o = json.loads(line)
    except Exception:
        continue
    key = (o.get("rule"), o.get("file"), o.get("line"))
    if key in seen:
        continue
    seen.add(key)
    dst.write(json.dumps({
        "tool": "js-analyzer", "rule": o.get("rule"), "severity": o.get("severity"),
        "file": o.get("file"), "line": o.get("line"), "message": o.get("title", ""),
        "next_step": o.get("next_step", ""),
    }) + "\n")
PY
  fi
fi

# Other languages: the dangerous-pattern table from the hunting methodology.
# Single-quoted so backticks/backslashes stay literal. A double-quoted `\\`` opened a
# command substitution and broke the whole script -- caught by `bash -n`.
declare -a PATTERNS=(
  'py-danger|--include=*.py|-e|pickle\.loads|yaml\.load\(|eval\(|exec\(|os\.system|subprocess'
  'php-danger|--include=*.php|-e|unserialize\(|eval\(|include\(|require\('
  'java-deser|--include=*.java|-e|ObjectInputStream|readObject|Runtime\.getRuntime|ProcessBuilder|XMLDecoder'
  'go-danger|--include=*.go|-e|template\.HTML|template\.JS|exec\.Command|os\.Exec'
  'rb-danger|--include=*.rb|-e|YAML\.load|Marshal\.load|eval\(|system\('
  'rs-danger|--include=*.rs|-e|unsafe \{|unwrap\(\)|expect\('
)
for spec in "${PATTERNS[@]}"; do
  IFS='|' read -r name inc flag pat <<< "$spec"
  [ -n "$name" ] || continue
  # shellcheck disable=SC2086
  grep -rn $inc "$flag" "$pat" "$src" 2>/dev/null | head -400 | while IFS= read -r line; do
    python3 -c "
import json,sys
line=sys.argv[1]
parts=line.split(':',2)
print(json.dumps({'tool':'patterns','rule':sys.argv[2],'severity':'medium','file':parts[0] if parts else '','line':parts[1] if len(parts)>1 else None,'message':(parts[2].strip()[:200] if len(parts)>2 else '')}))
" "$line" "$name" >> "$items"
  done || true
done

count=$(grep -c . "$items" 2>/dev/null || echo 0)
tools_run_json=$(printf '"%s",' "${tools_run[@]}" | sed 's/,$//')
tools_skipped_json=""
[ "${#tools_skipped[@]}" -gt 0 ] && tools_skipped_json=$(printf '%s,' "${tools_skipped[@]}" | sed 's/,$//')

cat > "$out/summary.json" <<EOF
{"phase":"18-source-audit","domain":"$domain","degraded":false,"count":$count,"tools_run":[$tools_run_json],"tools_skipped":[$tools_skipped_json],"items":[],"notes":["$count source-level lead(s) with file:line. These are LEADS, not findings: each needs a reachability argument and a runtime PoC before it is reportable."],"output_files":["$items"]}
EOF

mark_done "$domain" "recon-18"
echo '{"phase":"18","count":'"$count"'}'
