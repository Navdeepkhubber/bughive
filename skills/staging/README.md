# Staging

Raw skill files pulled in by `scripts/harvest-bb-skills.py`. Nothing here is
trusted or loaded into a hunt — `AGENTS.md`'s skill loading rule only covers
`skills/seeds/` and `skills/learned/`.

Each file carries an attribution comment (source repo, path, fetch date).
Before promoting anything out of this folder:

1. **Check the source repo's own license.** These are third-party repos,
   not this project's content; nothing here is blanket-MIT.
2. **Condense to house style.** Every real seed in `skills/seeds/*.md` is a
   ~100-200 word cheat sheet with custom section headers and raw payload
   lists — tighter than `skills/_schema.md`'s nominal cap, and nothing like
   the prose-heavy methodology docs these sources tend to ship (often
   2,000-4,000+ words). Rewrite, don't trim.
3. **Drop target-specific identifiers**, per `_schema.md`.
4. Move the finished file into `skills/seeds/`, dated and credited in the
   commit message, and delete the staged original.

Run the harvester manually: `python3 scripts/harvest-bb-skills.py`.
It shallow-clones the curated list in the script. A content hash that is
already staged is recorded as a duplicate and not written again. If every
source fails to clone, the process exits 1 and says the pipeline is broken.
Zero configured sources exits 2. A clone that succeeds and contains no skill
files is a real empty result and exits 0. `harvest-manifest.json` is the run
record and is gitignored.

The public Bug-Bounty-Skills aggregator is not a source. Its pipeline license
does not cover the skill text, and its source list includes red-team and
malware packs. This folder stays reference material.

## License gate

Staging files keep their upstream licenses. TruffleHog and BBOT are AGPL-3.0:
call the unmodified binaries, do not vendor them. Semgrep registry rules and
the CodeQL CLI are not harvested. nuclei-templates is MIT, but this repo does
not copy template text; `plugins/dsh-scan/pack.js` is an original pack in that
shape.

Promotion is a rewrite into `skills/seeds/` (see the house style above), then
delete that staged file. Seeds must not contain the `STAGING ONLY` or
`harvested:` markers. Classes rewritten as original seeds, not copied:
ssti, nosql, cors, race-condition, mass-assignment, secret-detection,
sca-advisory, tls.

