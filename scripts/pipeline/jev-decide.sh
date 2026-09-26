#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"

domain="$1"
node "$(dirname "$0")/jev-decide.mjs" "$domain"
mark_done "$domain" "decide"
