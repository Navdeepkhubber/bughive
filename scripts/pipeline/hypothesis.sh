#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"

domain="$1"
hd="$(hunt_dir "$domain")"

recon_json="$(for f in "$hd"/recon/*/summary.json; do
  [ -f "$f" ] && cat "$f" && echo
done | head -c 50000)"

# Hand the recon to the parent agent, which will write hypotheses.json
cat > "$hd/hypothesis-prompt.txt" <<EOF
You are the hypothesis agent for bughive.

Read these recon summaries and produce a ranked JSON array of testable
vulnerability hypotheses. Write the result to $hd/hypotheses.json.

For each hypothesis:
{
  "target": "<url or host>",
  "candidate": "<what to test>",
  "skill": "<suggested vuln-class skill>",
  "rationale": "<why>",
  "priority": 1-10,
  "baseline": {"method":"GET","url":"<url>"}
}

RECON SUMMARIES:
$recon_json
EOF

echo '{"phase":"hypothesis","prompt_file":"'"$hd"'/hypothesis-prompt.txt","next":"agent reads the prompt and writes hypotheses.json"}'
mark_done "$domain" "hypothesis"
