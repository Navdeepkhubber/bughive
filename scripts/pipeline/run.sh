#!/usr/bin/env bash
# bughive pipeline runner. The agent calls this with stage names.
set -euo pipefail
source "$(dirname "$0")/_common.sh"

stage="$1"; shift
case "$stage" in
  init)       cmd_init "$@" ;;
  status)     cmd_status "$@" ;;
  mark)       cmd_mark "$@" ;;
  recon-01|recon-02|recon-03|recon-04|recon-05|recon-06|recon-07|recon-08|recon-09|recon-10|recon-11|recon-12|recon-13|recon-14|recon-15|recon-16|recon-17)
    bash "$(dirname "$0")/${stage}.sh" "$@" ;;
  hypothesis) bash "$(dirname "$0")/hypothesis.sh" "$@" ;;
  skills)     bash "$(dirname "$0")/skill-select.sh" "$@" ;;
  decide)     bash "$(dirname "$0")/jev-decide.sh" "$@" ;;
  *) die "unknown stage: $stage" ;;
esac
