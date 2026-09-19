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
  for stage in scope recon-01 recon-02 recon-03 recon-04 recon-05 recon-06 recon-07 recon-08 recon-09 recon-10 recon-11 recon-12 recon-13 recon-14 recon-15 recon-16 recon-17 skills hypothesis prefilter falsifier proof chain report quality deliver; do
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
