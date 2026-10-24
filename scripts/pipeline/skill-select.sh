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
dsh_learned="${BUGHIVE_DSH_DIR:-$HOME/.dsh}/skills/learned"
# The GitHub workflow commits raw reports; the DSH classifier consumes a local
# queue and admits generated skills. Queue new reports before scoring, then
# include any skills the classifier has already admitted.
# The queue lives under $HOME/.dsh, which a workspace-write sandbox cannot
# write to. That bridge only feeds the classifier; it is not evidence for the
# hunt, so a refusal there must degrade the run rather than abort skill scoring.
if ! python3 "$WS_ROOT/intelligence/sync-report-queue.py" >/dev/null; then
  log "WARN report-queue sync skipped (cannot write ${BUGHIVE_DSH_DIR:-$HOME/.dsh}); scoring local skills only"
fi
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

for skill_file in "$skills_root"/seeds/*.md "$skills_root"/learned/*.md "$dsh_learned"/h1-*.md; do
  [ -f "$skill_file" ] || continue
  if [ "$(dirname "$skill_file")" = "$dsh_learned" ]; then
    [ ! -f "$skills_root/learned/$(basename "$skill_file")" ] || continue
    grep -q '^admitted:' "$skill_file" || continue
  fi
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

# --- Retrieval evidence -------------------------------------------------------
# Keyword overlap alone misses paraphrase: recon that says "the endpoint takes a file
# parameter and resolves it" never literally contains "lfi" or "traversal". The skill-rag
# plugin ranks by TF-IDF, so it catches those. Both signals are merged below; RAG can
# promote a skill that keyword scoring would have dropped entirely.
rag_json="$work/rag.json"
if [ -s "$work/corpus.lower.txt" ]; then
  node "$WS_ROOT/scripts/plugin-call.mjs" dsh-skill-rag retrieve_skills \
    "$(python3 -c 'import json,sys; print(json.dumps({"query": open(sys.argv[1]).read()[:20000], "k": 25}))' "$work/corpus.lower.txt")" \
    > "$rag_json" 2>/dev/null || : > "$rag_json"
else
  : > "$rag_json"
fi

# Merge, rank, and emit. Keeps the 8-skill budget; a skill qualifies on strong keyword
# evidence OR because retrieval ranked it highly.
python3 - "$results" "$rag_json" "$hd/skills-selected.json" "${ALWAYS_INCLUDE[@]}" <<'PY'
import json, sys

results_path, rag_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
forced = sys.argv[4:]

kw = {}
with open(results_path) as fh:
    for line in fh:
        parts = line.rstrip("\n").split("|")
        if len(parts) < 2 or not parts[1]:
            continue
        try:
            s = int(parts[0])
        except ValueError:
            continue
        kw[parts[1]] = {"score": s, "matched": parts[2] if len(parts) > 2 else ""}

rag = {}
try:
    with open(rag_path) as fh:
        data = json.load(fh)
    for rank, c in enumerate(data.get("candidates", [])):
        rag[c["id"]] = {"score": float(c.get("score", 0)), "rank": rank,
                        "matched": ",".join(c.get("matched_terms", [])[:6])}
except Exception:
    pass

merged = []
for skill in set(kw) | set(rag):
    k = kw.get(skill, {"score": 0, "matched": ""})
    r = rag.get(skill, {})
    kw_score = k["score"]
    rag_score = r.get("score", 0.0)
    rag_rank = r.get("rank")
    # Qualify on keyword evidence, or on retrieval ranking in the top 12.
    qualifies = kw_score >= 2 or (rag_rank is not None and rag_rank < 12)
    if not qualifies:
        continue
    reasons = []
    if kw_score >= 2:
        reasons.append(f"keyword overlap x{kw_score}")
    if rag_rank is not None and rag_rank < 12:
        reasons.append(f"tf-idf rank #{rag_rank + 1}")
    combined = kw_score + rag_score
    merged.append({
        "skill": skill,
        "score": round(combined, 3),
        "matched_terms": k["matched"] or r.get("matched", ""),
        "reason": " + ".join(reasons),
        "_sort": (kw_score >= 2, combined),
    })

merged.sort(key=lambda m: m["_sort"], reverse=True)
merged = merged[:8]

emitted = {m["skill"] for m in merged}
i = 0
lines = ["["]
for m in merged:
    m.pop("_sort", None)
    lines.append(("  " if i == 0 else " ,") + json.dumps(m))
    i += 1
for f in forced:
    sid = f"seeds/{f}"
    if sid in emitted:
        continue
    lines.append(("  " if i == 0 else " ,") + json.dumps({
        "skill": sid, "score": 0, "matched_terms": "",
        "reason": "flow/logic-class skill; no scorable evidence in this hunt's recon "
                  "(phase 11 may not have run) -- always considered as a safety net",
    }))
    i += 1
lines.append("]")
open(out_path, "w").write("\n".join(lines) + "\n")
print(json.dumps({"selected": i, "keyword_candidates": len(kw), "rag_candidates": len(rag)}))
PY

mark_done "$domain" "skills"
echo "{\"phase\":\"skills\",\"selected_file\":\"$hd/skills-selected.json\"}"
