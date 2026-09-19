#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"

# --- Fix: skill-loader used to be "the agent picks <=3 skills," with no
# scoring and no evidence trail. That's an arbitrary cap on a 31-skill
# library with no guarantee the right ones get loaded. This does a
# deterministic keyword-overlap match between each skill's own vocabulary
# and the actual recon corpus, so selection is evidence-based and
# auditable, and isn't capped below what the evidence supports.

domain="$1"
hd="$(hunt_dir "$domain")"
skills_root="$(dirname "$0")/../../skills"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Generic security-report words that appear in nearly every skill file and
# would just add noise if matched against recon data.
STOPWORDS='the|and|this|that|from|with|into|when|then|only|never|always|header|headers|technique|techniques|payload|payloads|trigger|triggers|params|param|parameter|parameters|vectors|vector|method|methods|value|values|using|after|before|each|other|than|more|less|some|most|also|both|none|true|false|output|input|response|request|target|targets|victim|attacker|bypass|bypasses|skill|skills|example|examples|generic|critical|medium|priority|severity|finding|findings|triage'

corpus="$work/corpus.txt"
: > "$corpus"
for f in "$hd"/recon/*/summary.json; do
  [ -f "$f" ] && cat "$f" >> "$corpus"
done
tr 'A-Z' 'a-z' < "$corpus" > "$work/corpus.lower.txt"

# Flow/logic-class skills used to have zero literal tokens to match against
# recon data, since recon was entirely static per-endpoint probing. Phase
# 11 (flow-mapping) now produces real evidence for these (e.g.
# "invite_acceptable_by_different_email", "2fa_step_skippable_via_direct_url"),
# so scoring can work for them -- but only on domains where phase 11
# actually ran and found a matching flow. Keep the forced include as a
# safety net for now (a hunt with no discovered flows would otherwise drop
# these entirely), but this is a candidate for removal once phase 11 has
# proven it reliably surfaces scorable evidence across real targets.
ALWAYS_INCLUDE=(business-logic account-takeover)

results="$work/results.txt"
: > "$results"

for skill_file in "$skills_root"/seeds/*.md "$skills_root"/learned/*.md; do
  [ -f "$skill_file" ] || continue
  base_id="$(basename "$skill_file" .md)"
  [ "$base_id" = "bughunter" ] && continue   # master skill, always loaded, not scored
  case "$skill_file" in
    */seeds/*)   skill_id="seeds/$base_id" ;;
    */learned/*) skill_id="learned/$base_id" ;;
  esac

  tokens="$(grep -oE '[a-zA-Z][a-zA-Z0-9_-]{3,}' "$skill_file" \
    | tr 'A-Z' 'a-z' \
    | grep -vE "^($STOPWORDS)$" \
    | sort -u)"

  score=0
  matched=()
  while IFS= read -r tok; do
    [ -z "$tok" ] && continue
    if grep -qF -- "$tok" "$work/corpus.lower.txt"; then
      score=$((score + 1))
      matched+=("$tok")
    fi
  done <<< "$tokens"

  # cap the evidence list shown per skill so the file stays readable
  matched_str="$(printf '%s,' "${matched[@]:0:6}" | sed 's/,$//')"
  echo "$score|$skill_id|$matched_str" >> "$results"
done

# Rank by score descending, keep anything with at least 2 distinct matches
# (arbitrary-but-explicit floor to cut pure noise), no arbitrary upper cap
# beyond a sane budget of 8 so the hypothesis prompt doesn't balloon.
ranked="$(sort -t'|' -k1,1 -rn "$results" | awk -F'|' '$1>=2' | head -8)"

{
  echo "["
  first=1
  emit() {
    local id="$1" score="$2" evidence="$3" reason="$4"
    [ "$first" -eq 1 ] || echo ","
    first=0
    printf '  {"skill":"%s","score":%s,"matched_terms":"%s","reason":"%s"}' \
      "$id" "$score" "$evidence" "$reason"
  }
  while IFS='|' read -r score id evidence; do
    [ -z "$id" ] && continue
    emit "$id" "$score" "$evidence" "keyword overlap with recon corpus"
  done <<< "$ranked"
  for forced in "${ALWAYS_INCLUDE[@]}"; do
    if ! grep -qE "\|seeds/${forced}\|" <<< "$ranked" 2>/dev/null; then
      emit "seeds/$forced" 0 "" "flow/logic-class skill; no scorable evidence found in this hunt's recon (phase 11 may not have run or found a matching flow) -- always considered as a safety net"
    fi
  done
  echo
  echo "]"
} > "$hd/skills-selected.json"

mark_done "$domain" "skills"
echo "{\"phase\":\"skills\",\"selected_file\":\"$hd/skills-selected.json\"}"
