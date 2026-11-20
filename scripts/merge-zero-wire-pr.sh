#!/usr/bin/env bash
# Validate a Cloudflare Zero Wire harvest pull request and squash-merge it.
#
# The workflow passes PR_NUMBER, PR_OPERATION, and PR_HEAD_SHA. An empty
# number, or an operation other than created/updated (no changes, feed 304,
# or a pull request closed because it no longer differs), skips the merge
# and exits 0.
#
# This script never force-pushes, never passes --admin, and never pushes
# straight to the default branch. A failed scope check, validation, check,
# or merge leaves the pull request open and exits non-zero.
#
#   bash scripts/merge-zero-wire-pr.sh --validate-only
# runs the same validation commands against the working tree.
#
# ZERO_WIRE_SKIP_SYNC=1 validates that working tree instead of fetching the
# pull request head. The workflow does not set it.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CHECK_REPORT_ATTEMPTS="${CHECK_REPORT_ATTEMPTS:-6}"
CHECK_REPORT_SLEEP_SECONDS="${CHECK_REPORT_SLEEP_SECONDS:-10}"
CHECK_WATCH_SECONDS="${CHECK_WATCH_SECONDS:-300}"

export GH_PAGER="${GH_PAGER:-cat}"
export PAGER="${PAGER:-cat}"
export GH_PROMPT_DISABLED="${GH_PROMPT_DISABLED:-1}"
export GIT_TERMINAL_PROMPT=0

validate_tree() {
  echo "Validation: python3 -m unittest tests/test_zero_wire.py"
  python3 -m unittest tests/test_zero_wire.py
  echo "Validation: node --test scripts/check-zero-wire-skills.mjs"
  node --test scripts/check-zero-wire-skills.mjs
}

if [ "${1:-}" = "--validate-only" ]; then
  validate_tree
  exit 0
fi

number="${PR_NUMBER:-}"
operation="${PR_OPERATION:-}"
head_sha="${PR_HEAD_SHA:-}"

if [ -z "$number" ] || { [ "$operation" != "created" ] && [ "$operation" != "updated" ]; }; then
  echo "No pull request was created or updated (operation=${operation:-none}). Skipping merge."
  exit 0
fi

if ! printf '%s' "$number" | grep -Eq '^[0-9]+$'; then
  echo "::error::Pull request number '${number}' is not numeric. Leaving the pull request open." >&2
  exit 1
fi

if [ -z "${GH_TOKEN:-}" ]; then
  echo "::error::GH_TOKEN is not set. Refusing to merge pull request #${number}." >&2
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "::error::gh is required to check and merge pull request #${number}." >&2
  exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
  echo "::error::timeout is required to bound gh pr checks --watch for pull request #${number}." >&2
  exit 1
fi

echo "Scope guard: gh pr diff ${number} --name-only"
diff_out="$(gh pr diff "$number" --name-only --color=never)"
if [ -z "$diff_out" ]; then
  echo "::error::Refusing to merge #${number}: gh pr diff returned no files. The pull request is left open." >&2
  exit 1
fi

outside=0
while IFS= read -r path; do
  [ -z "$path" ] && continue
  case "$path" in
    skills/cloudflare-zero-wire/*) ;;
    *)
      echo "::error::Refusing to merge #${number}: '${path}' is outside skills/cloudflare-zero-wire/." >&2
      outside=1
      ;;
  esac
done <<< "$diff_out"

if [ "$outside" -ne 0 ]; then
  echo "::error::Pull request #${number} is left open. This workflow only squash-merges changes under skills/cloudflare-zero-wire/." >&2
  exit 1
fi

if [ "${ZERO_WIRE_SKIP_SYNC:-}" = "1" ]; then
  echo "ZERO_WIRE_SKIP_SYNC=1: validating the working tree instead of the pull request head."
else
  if [ -z "$head_sha" ]; then
    echo "::error::pull-request-head-sha is empty. Refusing to merge #${number}." >&2
    exit 1
  fi
  echo "Fetching zero-wire-harvest to validate ${head_sha}"
  attempt=1
  fetched=""
  while [ "$attempt" -le 3 ]; do
    git fetch --no-tags origin zero-wire-harvest
    fetched="$(git rev-parse FETCH_HEAD)"
    if [ "$fetched" = "$head_sha" ]; then
      break
    fi
    echo "Fetched ${fetched}, waiting for pull request head ${head_sha} (attempt ${attempt}/3)."
    if [ "$attempt" -eq 3 ]; then
      echo "::error::zero-wire-harvest is ${fetched}, not pull request head ${head_sha}. Leaving #${number} open." >&2
      exit 1
    fi
    sleep 2
    attempt=$((attempt + 1))
  done
  if [ ! -f .github/workflows/harvest-zero-wire.yml ]; then
    echo "::error::Refusing to replace skills/cloudflare-zero-wire outside this repo. Leaving #${number} open." >&2
    exit 1
  fi
  rm -rf skills/cloudflare-zero-wire
  git checkout "$fetched" -- skills/cloudflare-zero-wire
fi

validate_tree

echo "Waiting for checks on pull request #${number}"
attempt=1
reported=0
check_status=1
while [ "$attempt" -le "$CHECK_REPORT_ATTEMPTS" ]; do
  set +e
  check_out="$(gh pr checks "$number" 2>&1)"
  check_status=$?
  set -e
  if printf '%s\n' "$check_out" | grep -q "no checks reported"; then
    echo "No checks reported on pull request #${number} yet (attempt ${attempt}/${CHECK_REPORT_ATTEMPTS})."
    if [ "$attempt" -eq "$CHECK_REPORT_ATTEMPTS" ]; then
      echo "::error::No checks reported on pull request #${number} after ${CHECK_REPORT_ATTEMPTS} attempts. The pull request is left open." >&2
      exit 1
    fi
    sleep "$CHECK_REPORT_SLEEP_SECONDS"
    attempt=$((attempt + 1))
    continue
  fi
  reported=1
  printf '%s\n' "$check_out"
  break
done

if [ "$reported" -ne 1 ]; then
  echo "::error::No checks reported on pull request #${number}. The pull request is left open." >&2
  exit 1
fi

if [ "$check_status" -eq 1 ]; then
  echo "::error::A check failed on pull request #${number}. The pull request is left open." >&2
  exit 1
fi

if [ "$check_status" -ne 0 ]; then
  echo "Checks are still running (gh pr checks exit ${check_status}). Watching for up to ${CHECK_WATCH_SECONDS}s."
  set +e
  timeout "$CHECK_WATCH_SECONDS" gh pr checks "$number" --watch --fail-fast --interval 10
  watch_status=$?
  set -e
  if [ "$watch_status" -eq 124 ] || [ "$watch_status" -eq 137 ] || [ "$watch_status" -eq 143 ]; then
    echo "::error::Timed out after ${CHECK_WATCH_SECONDS}s waiting for checks on pull request #${number}. The pull request is left open." >&2
    exit 1
  fi
  if [ "$watch_status" -ne 0 ]; then
    echo "::error::A check failed on pull request #${number} (gh pr checks --watch exit ${watch_status}). The pull request is left open." >&2
    exit 1
  fi
fi

echo "Squash-merging pull request #${number} with: gh pr merge ${number} --squash --delete-branch"
set +e
merge_out="$(gh pr merge "$number" --squash --delete-branch 2>&1)"
merge_status=$?
set -e
printf '%s\n' "$merge_out"
if [ "$merge_status" -ne 0 ]; then
  echo "::error::Squash-merge of pull request #${number} was refused (gh pr merge exit ${merge_status}). The pull request is left open. This workflow does not force-merge and does not push to the default branch." >&2
  exit 1
fi

echo "Squash-merged pull request #${number}."
