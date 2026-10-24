#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"

domain="$1"
hd="$(hunt_dir "$domain")"
dsh_learned="${BUGHIVE_DSH_DIR:-$HOME/.dsh}/skills/learned"

# --- Fix: prioritized, per-phase-budgeted recon assembly -------------------
# The old version concatenated summary.json in phase order (01..10) and cut
# the whole blob at 50000 bytes with `head -c`. On any real target that
# means phases 06-10 (param discovery, JS analysis, tech fingerprint,
# wayback, cloud assets) -- the phases that actually reveal attack surface --
# were silently the first thing dropped, because they sort/concatenate last.
# Fix: give every phase its own budget (so no phase can be starved to zero
# by an earlier one), and order high-signal phases first.
PER_PHASE_BUDGET=6000
GLOBAL_BUDGET=36000

# High-signal first (attack-surface-revealing), low-signal last
# (asset-discovery-only).
PHASE_ORDER=(
  "14-nuclei-scan"
  "15-mass-oneliners"
  "13-secret-scan"
  "17-interesting-endpoints"
  "16-github-dorking"
  "11-flow-mapping"
  "06-param-discovery"
  "07-js-analysis"
  "08-tech-fingerprint"
  "10-cloud-assets"
  "09-historical-data"
  "05-content-discovery"
  "04-http-probe"
  "01-subdomain-enum"
  "02-dns-resolution"
  "03-port-scan"
  "12-response-cache"
)

recon_json=""
total_bytes=0
skipped_phases=()

frontier_brief=""
if [ -f "$hd/evidence-frontier.json" ]; then
  frontier_brief="$(python3 - "$hd/evidence-frontier.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print(json.dumps({
  'routes':[{'key':r['key'],'url':r['url'],'score':r['score'],'signals':r['signals'],
             'evidence':r['evidence'][:3],'next_experiment':r['next_experiment']}
            for r in [r for r in d.get('routes',[]) if r.get('eligible')][:24]],
  'changes':d.get('changes',[])[:20],
  'parameter_candidates':d.get('parameter_candidates',[])[:20],
  'auth_replay_plans':d.get('auth_replay_plans',[])[:12],
  'technology_matches':d.get('technology_matches',[])[:12]
  ,'source_leads':d.get('source_leads',[])[:16],
  'js_parameter_candidates':d.get('js_parameter_candidates',[])[:30]
},separators=(',',':')))
PY
)"
fi

for phase_dir in "${PHASE_ORDER[@]}"; do
  f="$hd/recon/$phase_dir/summary.json"
  [ -f "$f" ] || continue
  phase_content="$(head -c "$PER_PHASE_BUDGET" "$f")"
  phase_bytes=${#phase_content}
  if [ "$((total_bytes + phase_bytes))" -gt "$GLOBAL_BUDGET" ]; then
    skipped_phases+=("$phase_dir")
    continue
  fi
  recon_json="${recon_json}${phase_content}
"
  total_bytes=$((total_bytes + phase_bytes))
done

skills_selected_json="[]"
if [ -f "$hd/skills-selected.json" ]; then
  skills_selected_json="$(cat "$hd/skills-selected.json")"
fi

jev_decision_json=""
if [ -f "$hd/jev-decision.json" ]; then
  jev_decision_json="$(cat "$hd/jev-decision.json")"
fi

skills_dump=""
if [ -f "$hd/skills-selected.json" ]; then
  # Pull the actual checklist body of every skill that was selected for this
  # target, so the hypothesis agent has the concrete techniques in front of
  # it instead of having to recall them.
  while IFS= read -r skill_id; do
    skill_path="$(dirname "$0")/../../skills/${skill_id}.md"
    [ -f "$skill_path" ] || skill_path="$(dirname "$0")/../../skills/${skill_id}"
    if [ ! -f "$skill_path" ] && [[ "$skill_id" == learned/* ]]; then
      skill_path="$dsh_learned/${skill_id#learned/}.md"
      grep -q '^admitted:' "$skill_path" 2>/dev/null || continue
    fi
    if [ -f "$skill_path" ]; then
      skills_dump="${skills_dump}
--- $skill_id ---
$(cat "$skill_path")
"
    fi
  done < <(python3 - "$hd/skills-selected.json" <<'PY'
import json, re, sys
for row in json.load(open(sys.argv[1])):
    skill = row.get('skill', '')
    if isinstance(skill, str) and re.fullmatch(r'(seeds|learned)/[A-Za-z0-9._ -]+', skill) and '..' not in skill:
        print(skill)
PY
)
fi

cat > "$hd/hypothesis-prompt.txt" <<EOF
You are the hypothesis agent for bughive.

Your job is NOT to brainstorm generic vulnerability ideas. It is to walk
each loaded skill's checklist line by line and check it against concrete
items in the recon data below. A hypothesis is only worth emitting if you
can point to a specific recon item (a URL, a param name, a header, a JS
string, a fingerprinted version) that matches a specific technique in a
specific skill. If you cannot cite a concrete recon item, do not emit the
hypothesis -- note in "notes" that the skill had no matching surface
instead of inventing a speculative one.

BINDING JEV DECISION:
If next_action is anything other than select_and_test, write hypotheses.json
as [] and stop. Prioritize the chosen "skill" / "vuln", "test_method", and
"focus_url", then inspect the other selected skills and tool hits for
independent concrete matches. Do not turn an endpoint name alone into a bug.
If chain_hypotheses is present, emit one hypothesis per entry. Cite the
standalone primitive and the partner it still needs. Keep the primitive;
it stays a lead until that partner is shown.
An unprobed host, truncated phase, or missing account is a coverage gap,
not a vulnerability hypothesis. Archive-only URLs and generic fuzzed paths
must first have current reachability and a differential control; do not
promote their path names or an undifferentiated 403/200 to priority 9-10.
$jev_decision_json

METHOD (do this explicitly, don't skip steps):
1. For each loaded skill below, read its checklist/technique list.
2. Scan the recon data for items matching that skill's trigger conditions
   (param names, endpoint patterns, response headers, JS strings, detected
   tech + version, cloud hints).
3. For every match, write one hypothesis. The "rationale" field MUST name
   the exact recon item and the exact skill technique it maps to -- e.g.
   "param 'redirect_uri' found at /oauth/callback (recon phase 06) matches
   oauth.md technique #4 (open redirect via unvalidated redirect_uri)".
   Do not write vague rationale like "could be vulnerable to X".
4. If a fingerprinted technology/version (phase 08) matches a known-CVE
   note in a loaded skill, treat that as a high-priority hypothesis.
4a. Phases 13 (secret-scan), 14 (nuclei-scan), 15 (mass-oneliners), and 16
    (github-dorking) are NOT hypotheses to re-derive -- they are
    deterministic, tool-confirmed hits. If any of them have count > 0,
    convert each item directly into an entry with priority 9-10 and
    rationale "tool-confirmed hit from phase <N>, not a derived hypothesis"
    -- do not spend reasoning re-justifying something a nuclei template or
    a qsreplace+httpx one-liner already confirmed. These should go straight
    to the falsifier stage to rule out template/tool false positives, not
    through the full skill-matching exercise the rest of this method
    describes.
4b. Phase 17 (interesting-endpoints) is a priority signal, not a
    confirmed hit like 4a's phases -- an /admin or /graphql match just
    means "look here first," it is not itself evidence of a bug. Weight
    hypotheses touching these endpoints higher, but they still need a
    real matched technique + evidence like everything else in this
    method.
5. If two skills both plausibly apply to the same endpoint, emit both --
   do not collapse them.
6. Rank by: (a) how concrete the recon evidence is, (b) potential impact
   per the skill's own Triage section.

Write the result to $hd/hypotheses.json as a JSON array. Shape per entry:
{
  "target": "<url or host>",
  "candidate": "<what to test>",
  "skill": "<skill id used, e.g. seeds/idor>",
  "matched_technique": "<the specific numbered/named technique from that skill>",
  "recon_evidence": "<the exact recon item, phase, and value that triggered this>",
  "rationale": "<why this is worth testing, referencing evidence + technique>",
  "priority": 1-10,
  "baseline": {"method":"GET","url":"<url>"}
}

SKILLS SELECTED FOR THIS TARGET (skills-selected.json):
$skills_selected_json

SKILL CHECKLISTS (full text of each selected skill):
$skills_dump

EVIDENCE FRONTIER (ranked route leads with source files; the score is a
search priority, never proof of a vulnerability):
$frontier_brief

Use the exact source file cited by a frontier item when raw evidence is
needed. Change and replay plans are leads only. Do not claim an auth bug from
response similarity, a CVE from product name alone, or XSS from reflection;
use the class-specific proof validator before any finding is validated.

RECON SUMMARIES (high-signal phases prioritized; some may be partial if a
phase's own summary exceeded its ${PER_PHASE_BUDGET}-byte slice -- check
$hd/recon/<phase>/ for full raw output if a hypothesis needs more detail):
$recon_json
EOF

skipped_note="[]"
if [ "${#skipped_phases[@]}" -gt 0 ]; then
  skipped_note="$(printf '"%s",' "${skipped_phases[@]}" | sed 's/,$//')"
  skipped_note="[$skipped_note]"
fi

echo '{"phase":"hypothesis","prompt_file":"'"$hd"'/hypothesis-prompt.txt","bytes_used":'"$total_bytes"',"phases_skipped_for_budget":'"$skipped_note"',"next":"agent reads the prompt and writes hypotheses.json"}'
# The hypothesis subagent has not written hypotheses.json yet. The parent
# records completion with run.sh mark after that artifact exists.
