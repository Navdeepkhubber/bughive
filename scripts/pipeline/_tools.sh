#!/usr/bin/env bash
# Pipeline helpers that expose the plugin tools to bash.
#
# Sourced by run.sh. Every function here exists because the corresponding capability was
# previously reachable only by the DSH agent, so real hunts never used it.

PLUGIN_CALL="$WS_ROOT/scripts/plugin-call.mjs"

# Thin wrapper: call a plugin tool, pass JSON back verbatim.
# Usage: plugin_call <plugin-dir> <tool> '<json>'
plugin_call() {
  local plugin="$1" tool="$2" args="${3:-{\}}"
  node "$PLUGIN_CALL" "$plugin" "$tool" "$args"
}

# JSON-encode a single string safely (avoids hand-rolled quoting bugs).
json_str() {
  python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

# ---------------------------------------------------------------- scope intake
# Parse a program's scope/policy page into scope.txt, and persist the policy
# exclusions so the triage stage can refuse a class the program forbids.
# Usage: run.sh scope <domain> <program-text-file>
cmd_scope() {
  local domain="$1" file="$2"
  [ -n "$domain" ] || die "usage: run.sh scope <domain> <program-text-file>"
  [ -n "$file" ] || die "usage: run.sh scope <domain> <program-text-file>"
  [ -f "$file" ] || die "no such file: $file"
  local hd; hd="$(hunt_dir "$domain")"
  mkdir -p "$hd"

  local out
  out="$(plugin_call dsh-scope-intake scope_txt "$(python3 -c 'import json,sys; print(json.dumps({"path": sys.argv[1]}))' "$file")")" \
    || die "scope parsing failed"

  # Persist both the parsed summary and a scope.txt for run.sh init / scope_guard.
  printf '%s\n' "$out" > "$hd/program-scope.json"
  printf '%s' "$out" | HD="$hd" python3 -c '
import json, os, sys
d = json.load(sys.stdin)
hd = os.environ["HD"]
txt = d.get("scope_txt", "").rstrip()
open(os.path.join(hd, "scope.txt"), "w").write(txt + "\n")
' || die "failed to write scope.txt"

  # Report from the full parse (scope_txt only carries counts).
  plugin_call dsh-scope-intake parse_program_scope \
    "$(python3 -c 'import json,sys; print(json.dumps({"path": sys.argv[1]}))' "$file")" \
    | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(json.dumps({
  "in_scope": d.get("in_scope", []),
  "out_of_scope": d.get("out_of_scope", []),
  "excluded_classes": d.get("excluded_classes", []),
  "policy_flags": [f["id"] for f in d.get("policy_flags", [])],
}))'
}

# -------------------------------------------------------------------- coverage
# Usage: run.sh coverage <init|gate|gaps|summary|mark> <domain> [extra-json]
cmd_coverage() {
  local sub="$1"; shift
  local domain="$1"; shift || true
  [ -n "$domain" ] || die "usage: run.sh coverage <init|gate|gaps|summary> <domain>"
  case "$sub" in
    init)    plugin_call dsh-coverage coverage_init "$(python3 -c 'import json,sys; print(json.dumps({"domain": sys.argv[1]}))' "$domain")" ;;
    gate)
      local out rc=0
      out="$(plugin_call dsh-coverage coverage_gate "$(python3 -c 'import json,sys; print(json.dumps({"domain": sys.argv[1]}))' "$domain")")" || rc=$?
      printf '%s\n' "$out"
      # Non-zero exit when the gate fails, so callers can block delivery on it.
      printf '%s' "$out" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("pass") else 1)' || exit 1
      ;;
    gaps)    plugin_call dsh-coverage coverage_gaps "$(python3 -c 'import json,sys; print(json.dumps({"domain": sys.argv[1], "criticalOnly": True}))' "$domain")" ;;
    summary) plugin_call dsh-coverage coverage_summary "$(python3 -c 'import json,sys; print(json.dumps({"domain": sys.argv[1]}))' "$domain")" ;;
    *)       die "unknown coverage subcommand: $sub" ;;
  esac
}

# ---------------------------------------------------------------- asset dedup
# Collapse clone/staging hosts from the phase-12 response cache, so the hunt tests the
# representative and treats siblings as leads.
# Usage: run.sh dedup <domain>
cmd_dedup() {
  local domain="$1"
  [ -n "$domain" ] || die "usage: run.sh dedup <domain>"
  local hd; hd="$(hunt_dir "$domain")"
  local cache="$hd/recon/12-response-cache"
  local out="$hd/recon/asset-clusters.json"
  if [ ! -d "$cache" ]; then
    echo '{"clusters":[],"note":"no response cache (phase 12) — nothing to dedup"}' | tee "$out"
    return 0
  fi
  plugin_call dsh-asset-dedup dedup_assets "$(python3 -c 'import json,sys; print(json.dumps({"paths": sys.argv[1]}))' "$cache")" | tee "$out"
}

# ---------------------------------------------------------------- live proxy
# Capture traffic from ANY process (raw curl, python, third-party binaries), not just the
# pipeline. This is the piece that made "proxy history" only half-true before.
# Usage: run.sh proxy <start|stop|requests|env> <domain> [--mitm]
PROXY_PORT="${BUGHIVE_PROXY_PORT:-8899}"

proxy_log()   { echo "$(hunt_dir "$1")/recon/proxy-capture.jsonl"; }
proxy_pid()   { echo "$(hunt_dir "$1")/.state/proxy.pid"; }

cmd_proxy() {
  local sub="$1"; shift || true
  local domain="$1"; shift || true
  [ -n "$domain" ] || die "usage: run.sh proxy <start|stop|requests|env> <domain> [--mitm]"
  local hd; hd="$(hunt_dir "$domain")"
  local log pidfile
  log="$(proxy_log "$domain")"
  pidfile="$(proxy_pid "$domain")"
  mkdir -p "$hd/recon" "$hd/.state"

  case "$sub" in
    start)
      local mitm_flag=""
      [ "${1:-}" = "--mitm" ] && mitm_flag="--mitm"
      if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        echo "{\"already_running\":true,\"proxy\":\"http://127.0.0.1:$PROXY_PORT\"}"
        return 0
      fi
      node "$WS_ROOT/plugins/dsh-proxy/proxy-cli.mjs" serve \
        --port "$PROXY_PORT" --log "$log" $mitm_flag >/dev/null 2>&1 &
      echo $! > "$pidfile"
      sleep 1
      if ! kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        rm -f "$pidfile"
        die "proxy failed to start (port $PROXY_PORT in use?)"
      fi
      echo "{\"started\":true,\"proxy\":\"http://127.0.0.1:$PROXY_PORT\",\"log\":\"$log\",\"mitm\":$([ -n "$mitm_flag" ] && echo true || echo false)}"
      ;;
    stop)
      if [ -f "$pidfile" ]; then
        kill "$(cat "$pidfile")" 2>/dev/null || true
        rm -f "$pidfile"
        echo '{"stopped":true}'
      else
        echo '{"stopped":false,"note":"not running"}'
      fi
      ;;
    requests)
      node "$WS_ROOT/plugins/dsh-proxy/proxy-cli.mjs" requests --log "$log" --limit "${1:-100}"
      ;;
    env)
      # Print shell exports so a caller can capture its own traffic.
      echo "export HTTP_PROXY=http://127.0.0.1:$PROXY_PORT"
      echo "export HTTPS_PROXY=http://127.0.0.1:$PROXY_PORT"
      echo "export http_proxy=http://127.0.0.1:$PROXY_PORT"
      echo "export https_proxy=http://127.0.0.1:$PROXY_PORT"
      ;;
    *) die "unknown proxy subcommand: $sub" ;;
  esac
}

# --------------------------------------------------------------- journal ingest
# Harvest request evidence into the journal, from BOTH recon output and the live proxy
# capture. This is what makes the hunt's request history complete.
# Usage: run.sh ingest <domain>
cmd_ingest() {
  local domain="$1"
  [ -n "$domain" ] || die "usage: run.sh ingest <domain>"
  local hd; hd="$(hunt_dir "$domain")"
  local paths="$hd/recon"
  local plog; plog="$(proxy_log "$domain")"
  [ -f "$plog" ] && paths="$paths
$plog"
  plugin_call dsh-hunt-journal hunt_journal_ingest \
    "$(python3 -c 'import json,sys; print(json.dumps({"domain": sys.argv[1], "paths": sys.argv[2]}))' "$domain" "$paths")"
}

# ------------------------------------------------------- visual asset hashing
# Screenshot every in-scope host once and perceptual-hash it, so clone/staging assets can
# be collapsed on how they LOOK, not just how their HTML reads.
# Usage: run.sh shots <domain>
cmd_shots() {
  local domain="$1"
  [ -n "$domain" ] || die "usage: run.sh shots <domain>"
  local hd; hd="$(hunt_dir "$domain")"
  [ -f "$hd/scope.txt" ] || die "no scope.txt for $domain"
  local out="$hd/recon/image-hashes.json"

  # Exclude `!` exclusions and comments; cap the list so a wide scope stays bounded.
  local urls
  urls="$(grep -v '^!' "$hd/scope.txt" | grep -v '^#' | grep -v '^\*' | head -25 | sed 's|^|https://|')"
  if [ -z "$urls" ]; then
    echo '{"hashed":0,"note":"no concrete hosts in scope (wildcards need resolving first)"}' | tee "$out"
    return 0
  fi

  plugin_call dsh-browser-validate hash_screenshots \
    "$(python3 -c 'import json,sys; print(json.dumps({"urls": sys.argv[1], "limit": 25}))' "$urls")" \
    | tee "$out" >/dev/null

  # Immediately cluster them, so the result is actionable rather than raw data.
  WS_ROOT="$WS_ROOT" python3 - "$out" "$hd/recon/image-clusters.json" <<'PY'
import json, subprocess, sys, os
src, dst = sys.argv[1], sys.argv[2]
data = json.load(open(src))
items = [{"id": i["id"], "dhash": i["dhash"]} for i in data.get("images", []) if i.get("dhash")]
if not items:
    json.dump({"clusters": [], "note": "nothing hashed"}, open(dst, "w"))
    raise SystemExit(0)
script = os.path.join(os.environ["WS_ROOT"], "scripts", "plugin-call.mjs")
out = subprocess.run(
    ["node", script, "dsh-asset-dedup", "dedup_by_hash", json.dumps({"items": json.dumps(items)})],
    capture_output=True, text=True)
open(dst, "w").write(out.stdout or "{}")
print(json.dumps({"hashed": len(items), "clusters_file": dst}))
PY
}

# ------------------------------------------------------------------ claim audit
# Verify a report's claims against the hunt's own evidence before it is submitted.
# Usage: run.sh audit <domain> <report.md>
cmd_audit() {
  local domain="$1" report="$2"
  [ -n "$report" ] || die "usage: run.sh audit <domain> <report.md>"
  [ -f "$report" ] || die "no such report: $report"
  local hd; hd="$(hunt_dir "$domain")"
  local out rc=0
  out="$(plugin_call dsh-claim-audit audit_report "$(python3 -c 'import json,sys; print(json.dumps({"reportPath": sys.argv[1], "evidencePaths": sys.argv[2]}))' "$report" "$hd")")" || rc=$?
  printf '%s\n' "$out"
  [ "$rc" -ne 0 ] && exit "$rc"
  printf '%s' "$out" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("pass") else 1)' || exit 1
}

# ------------------------------------------------------------------------ eval
# Usage: run.sh eval <scenarios|start|stop|score> [findings.json]
cmd_eval() {
  local sub="$1"; shift || true
  case "$sub" in
    scenarios) plugin_call dsh-eval eval_scenarios '{}' ;;
    start)     plugin_call dsh-eval eval_start_fixture '{}' ;;
    stop)      plugin_call dsh-eval eval_stop_fixture '{}' ;;
    score)
      local f="$1"
      [ -n "$f" ] && [ -f "$f" ] || die "usage: run.sh eval score <findings.json>"
      plugin_call dsh-eval eval_score "$(python3 -c 'import json,sys; print(json.dumps({"findings": open(sys.argv[1]).read()}))' "$f")"
      ;;
    *) die "unknown eval subcommand: $sub" ;;
  esac
}

# --------------------------------------------------------------- skill retrieval
# TF-IDF ranking over the skill library, as evidence for JEV.
# Usage: run.sh retrieve <domain>
cmd_retrieve() {
  local domain="$1"
  local hd; hd="$(hunt_dir "$domain")"
  local corpus="$hd/recon/skill-query.txt"
  if [ ! -f "$corpus" ]; then
    # Fall back to the concatenated recon summaries.
    cat "$hd"/recon/*/summary.json 2>/dev/null > "$corpus" || : > "$corpus"
  fi
  plugin_call dsh-skill-rag retrieve_skills "$(python3 -c 'import json,sys; print(json.dumps({"query": open(sys.argv[1]).read()[:20000], "k": 10}))' "$corpus")" \
    | tee "$hd/skills-rag.json"
}
