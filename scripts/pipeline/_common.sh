#!/usr/bin/env bash
set -euo pipefail

# Workspace root = bughive directory
WS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HUNTS="$WS_ROOT/hunts"

sanitize_domain() {
  local d="${1#https://}"; d="${d#http://}"
  d="${d%%/*}"; d="${d%%:*}"
  echo "$d" | tr '[:upper:]' '[:lower:]'
}

hunt_dir() { echo "$HUNTS/$(sanitize_domain "$1")"; }

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

stage_done() { [ -f "$(hunt_dir "$1")/.state/$2.done" ]; }
mark_done() {
  mkdir -p "$(hunt_dir "$1")/.state"
  date -u +%Y-%m-%dT%H:%M:%SZ > "$(hunt_dir "$1")/.state/$2.done"
}

# Phase directory for a recon-NN stage. Empty when the stage is not recon.
recon_phase_id() {
  case "$1" in
    recon-01) echo "01-subdomain-enum" ;;
    recon-02) echo "02-dns-resolution" ;;
    recon-03) echo "03-port-scan" ;;
    recon-04) echo "04-http-probe" ;;
    recon-05) echo "05-content-discovery" ;;
    recon-06) echo "06-param-discovery" ;;
    recon-07) echo "07-js-analysis" ;;
    recon-08) echo "08-tech-fingerprint" ;;
    recon-09) echo "09-historical-data" ;;
    recon-10) echo "10-cloud-assets" ;;
    recon-11) echo "11-flow-mapping" ;;
    recon-12) echo "12-response-cache" ;;
    recon-13) echo "13-secret-scan" ;;
    recon-14) echo "14-nuclei-scan" ;;
    recon-15) echo "15-mass-oneliners" ;;
    recon-16) echo "16-github-dorking" ;;
    recon-17) echo "17-interesting-endpoints" ;;
    recon-18) echo "18-source-audit" ;;
    *) echo "" ;;
  esac
}

# Outer backstop so a killed phase still returns. 0 means no extra timeout
# (phases that already bound themselves, or that legitimately run long).
recon_phase_timeout() {
  case "$1" in
    recon-03) echo "${BUGHIVE_RECON03_TIMEOUT:-180}" ;;
    recon-04) echo "${BUGHIVE_RECON04_TIMEOUT:-360}" ;;
    recon-09) echo "${BUGHIVE_RECON09_TIMEOUT:-180}" ;;
    *) echo "${BUGHIVE_RECON_PHASE_TIMEOUT:-0}" ;;
  esac
}

# Clock for the recon budget. Idle time between decide rounds is not counted;
# only seconds spent inside a recon stage are. The cap is therefore the
# accumulated runtime of recon, which is what a multi-minute httpx/nmap/gau
# chain burns, not wall time while a human is away.
recon_phase_begin() {
  local hd
  hd="$(hunt_dir "$1")"
  mkdir -p "$hd/.state"
  date +%s > "$hd/.state/recon-phase-start"
  if [ ! -f "$hd/.state/recon-wall-start" ]; then
    date -u +%Y-%m-%dT%H:%M:%SZ > "$hd/.state/recon-wall-start"
  fi
}

recon_phase_end() {
  local hd startf start now elapsed prev total
  hd="$(hunt_dir "$1")"
  startf="$hd/.state/recon-phase-start"
  [ -f "$startf" ] || return 0
  start="$(cat "$startf" 2>/dev/null || echo "")"
  rm -f "$startf"
  case "$start" in
    ""|*[!0-9]*) return 0 ;;
  esac
  now="$(date +%s)"
  elapsed=$((now - start))
  if [ "$elapsed" -lt 0 ]; then elapsed=0; fi
  if [ "$elapsed" -gt 86400 ]; then elapsed=86400; fi
  prev=0
  if [ -f "$hd/.state/recon-elapsed-seconds" ]; then
    prev="$(cat "$hd/.state/recon-elapsed-seconds" 2>/dev/null || echo 0)"
  fi
  case "$prev" in
    ""|*[!0-9]*) prev=0 ;;
  esac
  total=$((prev + elapsed))
  mkdir -p "$hd/.state"
  echo "$total" > "$hd/.state/recon-elapsed-seconds"
}

# A skipped or timed-out phase must leave summary.json behind. Without it the
# planner treats the phase as absent and selects it again forever.
# rc 124 (timeout) and rc 0 (skip that forgot the file) write a degraded
# summary and mark the stage done. Any other failure is left for the caller
# to surface; a crash is not relabelled as a finished phase.
ensure_recon_summary() {
  local domain="$1" stage="$2" rc="${3:-0}"
  local phase hd summary
  phase="$(recon_phase_id "$stage")"
  [ -n "$phase" ] || return 0
  hd="$(hunt_dir "$domain")"
  summary="$hd/recon/$phase/summary.json"
  mkdir -p "$(dirname "$summary")" "$hd/.state"
  if [ ! -f "$summary" ] && { [ "$rc" -eq 0 ] || [ "$rc" -eq 124 ]; }; then
    RECON_PHASE="$phase" RECON_DOMAIN="$(sanitize_domain "$domain")" RECON_RC="$rc" RECON_SUMMARY="$summary" \
      python3 - <<'PY'
import json, os
rc = os.environ.get("RECON_RC", "")
reason = (
    "phase timed out before summary.json was written"
    if rc == "124"
    else "phase ended without summary.json; marked degraded so it is not re-queued"
)
doc = {
    "phase": os.environ["RECON_PHASE"],
    "domain": os.environ["RECON_DOMAIN"],
    "count": 0,
    "degraded": True,
    "truncated": rc == "124",
    "tools_run": [],
    "notes": [reason],
    "output_files": [],
}
with open(os.environ["RECON_SUMMARY"], "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=2)
    fh.write("\n")
PY
  fi
  if [ "$rc" -eq 0 ] || [ "$rc" -eq 124 ]; then
    mark_done "$domain" "$stage"
  fi
}

cmd_init() {
  local domain="$1"; shift || true
  local scope="${1:-$domain}"
  local hd; hd="$(hunt_dir "$domain")"
  mkdir -p "$hd"/{recon,findings,chains,reports,logs,.state}
  printf '%s\n' "$scope" | grep -vE '^\s*(#|$)' | sed 's|^https\?://||; s|/.*$||; s|:.*$||' | sort -u > "$hd/scope.txt"
  echo "{\"domain\":\"$domain\",\"root\":\"$hd\",\"scope_count\":$(wc -l < "$hd/scope.txt")}"
  mark_done "$domain" "scope"
}

cmd_status() {
  local domain="$1"
  local hd; hd="$(hunt_dir "$domain")"
  echo "root: $hd"
  for stage in scope recon-01 recon-02 recon-03 recon-04 recon-05 recon-06 recon-07 recon-08 recon-09 recon-10 recon-11 recon-12 recon-13 recon-14 recon-15 recon-16 recon-17 skills decide hypothesis prefilter falsifier proof chain report quality deliver; do
    if [ -f "$hd/.state/$stage.done" ]; then printf "  ✓ %s\n" "$stage"; else printf "  · %s\n" "$stage"; fi
  done
}

cmd_mark() {
  local domain="$1" stage="$2"
  mark_done "$domain" "$stage"
  echo "{\"marked\":\"$stage\"}"
}

# Dispatch only when executed directly (`bash _common.sh cmd_init ...`).
# When sourced by run.sh / recon-*.sh this must NOT run, otherwise $@ is the
# caller's arguments and gets executed as a command.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  "$@"
fi
