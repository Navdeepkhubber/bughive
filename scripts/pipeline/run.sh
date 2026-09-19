#!/usr/bin/env bash
# bughive pipeline runner. The agent calls this with stage names.
set -euo pipefail
source "$(dirname "$0")/_common.sh"

stage="$1"; shift
case "$stage" in
  init)       cmd_init "$@" ;;
  status)     cmd_status "$@" ;;
  mark)       cmd_mark "$@" ;;
  recon-01|recon-02|recon-03|recon-04|recon-05|recon-06|recon-07|recon-08|recon-09|recon-10)
    bash "$(dirname "$0")/${stage}.sh" "$@" ;;
  hypothesis) bash "$(dirname "$0")/hypothesis.sh" "$@" ;;
  *) die "unknown stage: $stage" ;;
esac
