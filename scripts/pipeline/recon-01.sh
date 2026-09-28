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

tools_run=()
tools_skipped=()
: > "$out/raw-combined.txt"

if command -v subfinder >/dev/null 2>&1; then
  tools_run+=("subfinder")
  for root in "${enum_roots[@]}"; do
    log "subfinder $root (passive)"
    timeout 90 subfinder -d "$root" -silent -o "$out/raw-subfinder-$root.txt" 2>/dev/null || true
    if [ -s "$out/raw-subfinder-$root.txt" ]; then cat "$out/raw-subfinder-$root.txt" >> "$out/raw-combined.txt"; fi
  done
else
  tools_skipped+=('{"tool":"subfinder","reason":"not installed"}')
fi

if command -v amass >/dev/null 2>&1; then
  tools_run+=("amass")
  for root in "${enum_roots[@]}"; do
    log "amass enum -passive $root"
    timeout 150 amass enum -passive -d "$root" -silent -o "$out/raw-amass-$root.txt" 2>/dev/null || true
    if [ -s "$out/raw-amass-$root.txt" ]; then cat "$out/raw-amass-$root.txt" >> "$out/raw-combined.txt"; fi
  done
else
  tools_skipped+=('{"tool":"amass","reason":"not installed"}')
fi

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

summary = {
    "phase": "01-subdomain-enum",
    "domain": hd.name,
    "mode": "passive",
    "enumeration_roots": enum_roots(scope_text),
    "tools_run": tools_run,
    "tools_skipped": tools_skipped,
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
    "notes": [
        "assets.txt is the wildcard-expanded, scope-verified host list that later phases must use.",
        "scope.txt remains the program scope verbatim (wildcards included) and is what scope_guard enforces.",
    ],
}
(out / "summary.json").write_text(json.dumps(summary, indent=2))
print(json.dumps({
    "phase": "01",
    "discovered": len(all_hosts),
    "in_scope": len(assets),
    "out_of_scope": len(refused),
    "unresolved_wildcards": unresolved,
}))
PY

mark_done "$domain" "recon-01"
