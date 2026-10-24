# Staging

Raw skill files from `skills/sources.txt`, written by `scripts/harvest-bb-skills.py`.
This directory is not loaded. The hunt loader reads `skills/seeds/` and
`skills/learned/` only.

```bash
bash scripts/pipeline/run.sh harvest          # clone the source list
bash scripts/pipeline/run.sh harvest --dry-run
bash scripts/pipeline/run.sh ingest-skills    # promote into learned/ and missing seeds
bash scripts/pipeline/run.sh ingest-skills --dry-run
```

The same two steps are jobs in `.github/workflows/sync-reports-and-skills.yml`,
after the HackerOne fetch. `--dry-run` prints the plan and writes nothing.

Each staged file starts with a provenance header: source repo, path, fetch
date, author, license, and commit. A later harvest that sees the same body
backfills author, commit, or license and keeps the original fetch date.
`harvest-manifest.json` is the run record and is gitignored. Zero sources
exits 2. Every clone failing exits 1. A clone with no skill files exits 0.

`node scripts/ingest-staging.mjs` then:

1. Classifies each `*.staged.md` from its filename. No single class, or more
   than one, is flagged in `skills/ingest-report.json` and left here.
2. Writes `skills/learned/staged-<name>.md` in the house schema from
   `skills/_schema.md`, with the provenance comment kept.
3. Copies the staged body under `## Source text` only for MIT, Apache, BSD,
   ISC, or Unlicense. Every other license becomes original house text. The
   staged sentences are not copied.
4. Creates `skills/seeds/<class>.md` when that seed does not exist. An
   existing seed is not rewritten.
5. Writes the same report on a second run when nothing changed, and deletes
   a `skills/learned/staged-*.md` file that no longer has a staged source.
   `h1-*.md` files are left alone.

The public Bug-Bounty-Skills aggregator is not a source. TruffleHog and BBOT
are AGPL-3.0 and are not harvested. Semgrep registry rules and the CodeQL CLI
are not harvested. nuclei-templates is MIT; this repo does not copy template
text.
