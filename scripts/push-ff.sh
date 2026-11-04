#!/usr/bin/env bash
# Push HEAD to origin/<branch> as a fast-forward.
#
# actions/checkout@v4, with no ref input, pins the job to the workflow SHA
# (a depth-1 fetch). Later jobs in this workflow already wait via `needs:`,
# but they still commit on that stale SHA. After an earlier job pushes,
# `git push` is rejected with "fetch first". Fetch the current tip of the
# checked-out branch, rebase the local commit onto it, then push. Retry
# when the tip moves again between rebase and push. A rebase conflict
# fails the job; this script never force-pushes.
set -euo pipefail

branch="${1:-}"
if [ -z "$branch" ]; then
  branch="$(git rev-parse --abbrev-ref HEAD)"
fi
if [ -z "$branch" ] || [ "$branch" = "HEAD" ]; then
  echo "::error::detached HEAD; pass the branch name to push" >&2
  exit 1
fi
attempts="${PUSH_ATTEMPTS:-5}"
if [ -n "${PUSH_RETRY_SLEEP_SECONDS+x}" ]; then
  sleep_seconds() { sleep "$PUSH_RETRY_SLEEP_SECONDS"; }
else
  sleep_seconds() { sleep $((attempt * 2)); }
fi

git_dir="$(git rev-parse --git-dir)"
if [ -d "$git_dir/rebase-merge" ] || [ -d "$git_dir/rebase-apply" ]; then
  echo "::error::a rebase is already in progress" >&2
  exit 1
fi

attempt=1
while [ "$attempt" -le "$attempts" ]; do
  if [ "$(git rev-parse --is-shallow-repository)" = "true" ]; then
    # Bring in commits that landed after the pinned SHA. --deepen keeps the
    # shared parent that a depth-1 tip fetch can drop.
    git fetch --deepen=50 origin "$branch"
  else
    git fetch origin "$branch"
  fi

  if ! git rebase "origin/${branch}"; then
    git rebase --abort || true
    echo "::error::rebase onto origin/${branch} conflicted; not pushing" >&2
    exit 1
  fi

  if git push origin "HEAD:${branch}"; then
    exit 0
  fi

  echo "git push rejected (attempt ${attempt}/${attempts}); fetching and retrying" >&2
  sleep_seconds
  attempt=$((attempt + 1))
done

echo "::error::git push to origin/${branch} failed after ${attempts} attempts" >&2
exit 1
