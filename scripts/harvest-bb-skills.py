#!/usr/bin/env python3
"""
Bug-bounty skill harvester (staging only).

Shallow-clones a short, curated list of bug-bounty-specific source repos
(not a broad aggregator sweep) and copies their *.md skill files into
skills/staging/ — never directly into skills/seeds/ or skills/learned/.

Why staging and not seeds/: every real seed in this repo (see
skills/seeds/*.md) is a hand-written, ~100-200 word cheat sheet in a dense
house style with custom section headers and raw payload lists — much
tighter than skills/_schema.md's nominal 1000-token cap, and nothing like
upstream repos' prose-heavy methodology docs (2,000-4,000+ words each).
A harvested file is reference material for a human (or a review subagent)
to condense into that house style, cite, and license-check — not something
to trust or load into a live hunt as-is.

Each staged file keeps an attribution header: source repo, path, fetched
date. Licensing is NOT MIT-blanket — each source repo keeps its own
license, so check before promoting any content out of staging.

Uses `git clone --depth 1` (no GitHub API calls, so it needs no token and
isn't subject to REST API rate limits). Requires `git` on PATH.
"""

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STAGING_DIR = os.path.join(ROOT, "skills", "staging")

# Curated, not the whole aggregator list: repos that are actually
# bug-bounty/offensive-security skill packs, not general business/eng
# collections swept in along the way. Add lines here deliberately.
SOURCES = [
    "ctahok/hermes-bug-bounty-skills",
    "0x002132/skills-bugbounty",
    "Aetherdz/huntpack",
    "murraywu/Bug-Bounty-Skills",
    "Gabson0x/bountyforge",
]

MAX_BYTES_PER_FILE = 1_000_000
CLONE_TIMEOUT_SECS = 120


def flat_name(repo: str, rel_path: str) -> str:
    owner, repo_name = repo.split("/")
    parts = [p for p in rel_path.split(os.sep) if p.lower() != "skill.md"]
    stem = "-".join([owner, repo_name] + parts)
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", stem).strip("-")
    if len(stem) > 150:
        stem = stem[:140] + "-" + hashlib.sha256(stem.encode()).hexdigest()[:8]
    return stem + ".staged.md"


def clone(repo: str, dest: str) -> bool:
    url = f"https://github.com/{repo}"
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", url, dest],
            check=True,
            timeout=CLONE_TIMEOUT_SECS,
            env={**os.environ, "GIT_LFS_SKIP_SMUDGE": "1"},
        )
        return True
    except subprocess.TimeoutExpired:
        print(f"  ! clone timed out after {CLONE_TIMEOUT_SECS}s", flush=True)
        return False
    except subprocess.CalledProcessError as e:
        print(f"  ! clone failed: {e}", flush=True)
        return False


def main() -> int:
    os.makedirs(STAGING_DIR, exist_ok=True)

    written = 0
    present = 0
    skipped = 0
    total = 0

    for repo in SOURCES:
        print(f"[{repo}] cloning", flush=True)
        with tempfile.TemporaryDirectory(prefix="bbskill-") as tmp:
            clone_dir = os.path.join(tmp, "repo")
            if not clone(repo, clone_dir):
                print(f"[{repo}] skipping (clone failed)", flush=True)
                continue

            md_files = []
            for dirpath, dirnames, filenames in os.walk(clone_dir):
                if ".git" in dirnames:
                    dirnames.remove(".git")
                for fn in filenames:
                    if fn.lower().endswith(".md") and "skill" in fn.lower():
                        md_files.append(os.path.join(dirpath, fn))

            print(f"[{repo}] {len(md_files)} candidate file(s)", flush=True)

            for full_path in md_files:
                total += 1
                rel_path = os.path.relpath(full_path, clone_dir)
                size = os.path.getsize(full_path)
                if size > MAX_BYTES_PER_FILE:
                    print(f"  ! skipped {rel_path} ({size} bytes > cap)", flush=True)
                    skipped += 1
                    continue

                with open(full_path, encoding="utf-8", errors="replace") as f:
                    body = f.read()

                fetched = datetime.now(timezone.utc).isoformat()
                attributed = (
                    f"<!-- harvested: {repo}/{rel_path.replace(os.sep, '/')} on {fetched} -->\n"
                    f"<!-- STAGING ONLY -- condense to skills/_schema.md house style, "
                    f"verify the source repo's license, then promote to skills/seeds/ -->\n\n"
                    f"{body}"
                )

                dest = os.path.join(STAGING_DIR, flat_name(repo, rel_path))
                if os.path.exists(dest):
                    with open(dest, encoding="utf-8") as f:
                        old = f.read()
                    # Compare ignoring the attribution header (its date always differs).
                    if old.split("\n\n", 2)[-1] == attributed.split("\n\n", 2)[-1]:
                        present += 1
                        continue
                with open(dest, "w", encoding="utf-8") as f:
                    f.write(attributed)
                written += 1

    print(
        f"\nDONE: {written} new/updated, {present} already present, "
        f"{skipped} skipped (too large), {total} files scanned -> skills/staging/"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
