# Agent: skill-loader
Role: Selects vuln-class skills matching the target profile, using an
evidence-based score rather than a flat guess.
Model: DeepSeek V4.1 Flash

Method: `scripts/pipeline/skill-select.sh <domain>` does deterministic
keyword-overlap scoring between every skill file's own vocabulary and the
actual recon corpus (params, JS strings, fingerprinted tech, etc.). That
file is evidence. `scripts/pipeline/run.sh decide <domain>` then asks JEV
which skill to load, which vulnerability to test, and which test method
to use, and rewrites `hunts/<domain>/skills-selected.json` to the skills
JEV kept. The keyword shortlist is preserved at `skills-keyword.json`.

Constraints: always loads bughunter.md first (master skill, not scored) ·
JEV keeps at most 8 skills, and only those whose confirm probability is at
least 0.4 · keyword evidence stays in skills-keyword.json · never modifies
the skill library · read-only.
Escalation: if the score-based selection looks wrong for a known target
type (e.g. a fingerprinted CMS didn't surface its dedicated skill), add it
manually and note why the automated match missed it -> parent.
