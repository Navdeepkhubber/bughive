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

Run the harvester manually: `python3 scripts/harvest-bb-skills.py`
(`GITHUB_TOKEN` env var optional, raises the GitHub API rate limit).
