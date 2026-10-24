#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"

domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/01-subdomain-enum"
script_dir="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$out"
cp "$hd/scope.txt" "$out/scope.txt"

# Passive enumeration.
#
# Scope is normally wildcard-only (`*.synedra.com`), so the roots to enumerate are
# derived from the scope patterns rather than from $domain alone -- otherwise
# `.cloud` / `.net` siblings are never discovered.
enum_roots=()
while IFS= read -r r; do
  [ -n "$r" ] && enum_roots+=("$r")
done < <(python3 "$script_dir/_scope.py" enum-roots "$hd/scope.txt" 2>/dev/null || true)
if [ "${#enum_roots[@]}" -eq 0 ]; then enum_roots=("$domain"); fi
log "enumeration roots: ${enum_roots[*]}"

# One phase budget for every root. A 30-domain VDP must not spend 90s on each
# root and never leave enumeration. Partial names are kept and flagged.
eval "$(python3 "$script_dir/_batch.py" exports)"
enum_budget="${BUGHIVE_SUBFINDER_BUDGET_SECONDS:-300}"
sub_per="${BUGHIVE_SUBFINDER_PER_ROOT_SECONDS:-90}"
amass_per="${BUGHIVE_AMASS_PER_ROOT_SECONDS:-150}"
enum_deadline=$(( $(date +%s) + enum_budget ))
truncated=0

within_budget() {
  # Prints the timeout to use. Exit 1 when the phase budget is already spent.
  # Runs in a command substitution, so it must not rely on updating caller state.
  local per="$1" left
  left=$(( enum_deadline - $(date +%s) ))
  if [ "$left" -lt 8 ]; then
    echo 0
    return 1
  fi
  if [ "$left" -gt "$per" ]; then left="$per"; fi
  echo "$left"
  return 0
}

tools_run=()
tools_skipped=()
: > "$out/raw-combined.txt"

if command -v subfinder >/dev/null 2>&1; then
  tools_run+=("subfinder")
  for root in "${enum_roots[@]}"; do
    if ! left="$(within_budget "$sub_per")"; then
      truncated=1
      log "subfinder budget exhausted; remaining roots skipped"
      break
    fi
    log "subfinder $root (passive, ${left}s)"
    timeout "$left" subfinder -d "$root" -silent -o "$out/raw-subfinder-$root.txt" 2>/dev/null || true
    if [ -s "$out/raw-subfinder-$root.txt" ]; then cat "$out/raw-subfinder-$root.txt" >> "$out/raw-combined.txt"; fi
  done
else
  tools_skipped+=('{"tool":"subfinder","reason":"not installed"}')
fi

if command -v amass >/dev/null 2>&1; then
  tools_run+=("amass")
  for root in "${enum_roots[@]}"; do
    if ! left="$(within_budget "$amass_per")"; then
      truncated=1
      log "amass budget exhausted; remaining roots skipped"
      break
    fi
    log "amass enum -passive $root (${left}s)"
    timeout "$left" amass enum -passive -d "$root" -silent -o "$out/raw-amass-$root.txt" 2>/dev/null || true
    if [ -s "$out/raw-amass-$root.txt" ]; then cat "$out/raw-amass-$root.txt" >> "$out/raw-combined.txt"; fi
  done
else
  tools_skipped+=('{"tool":"amass","reason":"not installed"}')
fi
printf '%s\n' "$truncated" > "$out/.enum-truncated"

# Normalise to bare hostnames and de-duplicate.
tr -d '\r' < "$out/raw-combined.txt" 2>/dev/null \
  | sed -E 's#^https?://##; s#/.*$##; s#:[0-9]+$##; s/[[:space:]]+//g' \
  | tr '[:upper:]' '[:lower:]' \
  | grep -E '^[a-z0-9][a-z0-9._-]*\.[a-z]{2,}$' \
  | sort -u > "$out/all-hosts.txt" || : > "$out/all-hosts.txt"

# Hand the tool bookkeeping to the classifier as plain files (bash 3.2 has no mapfile,
# and building JSON in shell quoting is a reliable source of malformed summaries).
: > "$out/.tools-run"
if [ "${#tools_run[@]}" -gt 0 ]; then
  for t in "${tools_run[@]}"; do printf '%s\n' "$t" >> "$out/.tools-run"; done
fi
: > "$out/.tools-skipped"
if [ "${#tools_skipped[@]}" -gt 0 ]; then
  for t in "${tools_skipped[@]}"; do printf '%s\n' "$t" >> "$out/.tools-skipped"; done
fi

# Scope classification. Uses the same wildcard-aware matcher as the dsh-scope-guard
# enforcement tool (see _scope.py). An exact-string or endsWith comparison classifies
# every in-scope subdomain as OUT of scope when the program scope is wildcard-only.
python3 - "$out" "$hd" "$script_dir" <<'PY'
import json, sys
from pathlib import Path

sys.path.insert(0, sys.argv[3])
from _scope import scope_allows, parse_scope, pattern_to_regex, literal_roots, enum_roots

out, hd = Path(sys.argv[1]), Path(sys.argv[2])

def lines(path):
    return [l.strip() for l in path.read_text().splitlines() if l.strip()] if path.exists() else []

tools_run = lines(out / ".tools-run")
tools_skipped = []
for line in lines(out / ".tools-skipped"):
    try:
        tools_skipped.append(json.loads(line))
    except json.JSONDecodeError:
        tools_skipped.append({"tool": line, "reason": "unknown"})

scope_text = (hd / "scope.txt").read_text()
all_hosts = sorted(set(lines(out / "all-hosts.txt")))
try:
    enum_truncated = (out / ".enum-truncated").read_text().strip() == "1"
except OSError:
    enum_truncated = False

allowed, refused = [], []
for host in all_hosts:
    ok, _reason = scope_allows(scope_text, host)
    (allowed if ok else refused).append(host)

# Concrete hosts named by the scope are assets even when discovery missed them.
assets = sorted(set(allowed) | set(literal_roots(scope_text)))

include, _exclude = parse_scope(scope_text)
unresolved = []
for pat in include:
    if "*" not in pat:
        continue
    rx = pattern_to_regex(pat)
    if not any(rx.match(h) for h in all_hosts):
        unresolved.append(pat)

(out / "assets.txt").write_text("".join(f"{h}\n" for h in assets))
(out / "in-scope-hosts.txt").write_text("".join(f"{h}\n" for h in allowed))

# Zero enumerators is the S1N6H-Recon failure mode: the phase still exits, but
# count 0 must not be read as "this target has no hosts".
degraded = len(tools_run) == 0 or enum_truncated
notes = [
    "assets.txt is the wildcard-expanded, scope-verified host list that later phases must use.",
    "scope.txt remains the program scope verbatim (wildcards included) and is what scope_guard enforces.",
]
if enum_truncated:
    notes.append(
        "enumeration hit its wall-clock budget; remaining roots were skipped and this phase is truncated"
    )
if len(tools_run) == 0:
    notes.append(
        "0 discovery tools ran. count 0 is a coverage gap, not proof the target has no hosts. "
        "Install subfinder or amass. Literal hosts already named in scope.txt are still listed."
    )

summary = {
    "phase": "01-subdomain-enum",
    "domain": hd.name,
    "mode": "passive",
    "enumeration_roots": enum_roots(scope_text),
    "tools_run": tools_run,
    "tools_skipped": tools_skipped,
    "degraded": degraded,
    "truncated": bool(enum_truncated),
    "count_total_discovered": len(all_hosts),
    "count_in_scope": len(assets),
    "in_scope_confirmed": assets,
    "in_scope_wildcard_patterns_unresolved": unresolved,
    "out_of_scope_count": len(refused),
    "out_of_scope_found": refused[:100],
    "output_files": [
        str(out / "all-hosts.txt"),
        str(out / "assets.txt"),
        str(out / "scope.txt"),
    ],
    "notes": notes,
}
(out / "summary.json").write_text(json.dumps(summary, indent=2))
print(json.dumps({
    "phase": "01",
    "discovered": len(all_hosts),
    "in_scope": len(assets),
    "out_of_scope": len(refused),
    "unresolved_wildcards": unresolved,
    "degraded": degraded,
    "truncated": bool(enum_truncated),
    "tools_run": len(tools_run),
    "tools_skipped": len(tools_skipped),
}))
PY

mark_done "$domain" "recon-01"
