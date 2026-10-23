#!/usr/bin/env python3
"""
Bug-bounty skill harvester (staging only).

Shallow-clones a short, curated list of bug-bounty skill repos and copies
matching markdown into skills/staging/. Nothing is written to skills/seeds/
or skills/learned/, and a harvested file is never loaded into a hunt.

The collector in S1N6H/Bug-Bounty-Skills (MIT for the pipeline, not for the
skill text) dedupes by content hash and encodes owner/repo/path in the
filename. This script does that, and stops there. It does not import that
repo's aggregator source list, and it does not treat a failed clone as an
empty harvest.

Each staged file keeps an attribution header: source repo, path, fetch time,
and a short license hint read from the source repo. The hint is not permission
to promote the file.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STAGING_DIR = os.path.join(ROOT, "skills", "staging")

# Curated on purpose. The public aggregator list also pulls red-team, malware,
# and general assistant packs. Those stay out until someone license-checks and
# rewrites a single class.
SOURCES = [
    "ctahok/hermes-bug-bounty-skills",
    "0x002132/skills-bugbounty",
    "Aetherdz/huntpack",
    "murraywu/Bug-Bounty-Skills",
    "Gabson0x/bountyforge",
]

MAX_BYTES_PER_FILE = 1_000_000
CLONE_TIMEOUT_SECS = 120
MANIFEST_NAME = "harvest-manifest.json"


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def strip_header(text: str) -> str:
    if text.startswith("<!-- harvested:"):
        return text.split("\n\n", 1)[-1]
    return text


def classify_license(text: str) -> str:
    head = text[:2000]
    spdx = re.search(r"SPDX-License-Identifier:\s*([A-Za-z0-9.+-]+)", head)
    if spdx:
        return spdx.group(1)
    checks = (
        ("AGPL-3.0", r"GNU AFFERO"),
        ("GPL-3.0", r"GNU GENERAL PUBLIC LICENSE"),
        ("Apache-2.0", r"Apache License"),
        ("MIT", r"Permission is hereby granted|MIT License"),
        ("BSD-3-Clause", r"BSD 3-Clause|Redistribution and use in source"),
    )
    for label, pattern in checks:
        if re.search(pattern, head, re.IGNORECASE):
            return label
    return "unspecified"


def license_hint(repo_dir: str) -> str:
    for name in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.txt"):
        path = os.path.join(repo_dir, name)
        if os.path.isfile(path):
            with open(path, encoding="utf-8", errors="replace") as handle:
                return classify_license(handle.read(2000))
    return "unspecified"


def flat_name(repo: str, rel_path: str) -> str:
    owner, repo_name = repo.split("/")
    parts = [p for p in rel_path.split("/") if p.lower() != "skill.md"]
    stem = "-".join([owner, repo_name] + parts)
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", stem).strip("-")
    if len(stem) > 150:
        stem = stem[:140] + "-" + hashlib.sha256(stem.encode()).hexdigest()[:8]
    return stem + ".staged.md"


def refuse_loaded_dirs(staging_dir: str, root: str) -> None:
    staging = os.path.realpath(staging_dir)
    for name in ("seeds", "learned"):
        banned = os.path.realpath(os.path.join(root, "skills", name))
        if staging == banned or staging.startswith(banned + os.sep):
            raise RuntimeError(f"refusing to harvest into skills/{name}")


def list_skill_files(repo_dir: str):
    found = []
    for dirpath, dirnames, filenames in os.walk(repo_dir):
        if ".git" in dirnames:
            dirnames.remove(".git")
        for filename in filenames:
            if filename.lower().endswith(".md") and "skill" in filename.lower():
                found.append(os.path.join(dirpath, filename))
    return found


def index_existing(staging_dir: str):
    by_hash = {}
    by_name = {}
    if not os.path.isdir(staging_dir):
        return by_hash, by_name
    for name in os.listdir(staging_dir):
        if not name.endswith(".md") or name.lower() == "readme.md":
            continue
        path = os.path.join(staging_dir, name)
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8", errors="replace") as handle:
            body = strip_header(handle.read())
        digest = content_hash(body)
        by_hash.setdefault(digest, name)
        by_name[name] = digest
    return by_hash, by_name


def attribute(repo: str, rel_path: str, fetched: str, license_name: str, body: str) -> str:
    rel = rel_path.replace(os.sep, "/")
    return (
        f"<!-- harvested: {repo}/{rel} on {fetched} -->\n"
        f"<!-- license: {license_name}; source repo license, not permission to load or promote -->\n"
        "<!-- STAGING ONLY -- condense to skills/_schema.md house style, "
        "verify the source repo's license, then promote to skills/seeds/ -->\n\n"
        f"{body}"
    )


def clone_repo(repo: str, dest: str) -> bool:
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
    except subprocess.CalledProcessError as error:
        print(f"  ! clone failed: {error}", flush=True)
        return False


def harvest_sources(sources, staging_dir, clone, now, root) -> dict:
    refuse_loaded_dirs(staging_dir, root)
    os.makedirs(staging_dir, exist_ok=True)
    by_hash, by_name = index_existing(staging_dir)
    entries = []
    written = present = duplicates = skipped = 0
    failed = []
    cloned = 0

    if not sources:
        result = {
            "exit_code": 2,
            "written": 0,
            "present": 0,
            "duplicates": 0,
            "skipped": 0,
            "failed_sources": [],
            "cloned": 0,
            "files": [],
            "verdict": "PIPELINE BROKEN: 0 harvest sources configured. This is not an empty skill library.",
        }
        _write_manifest(staging_dir, sources, result)
        return result

    for repo in sources:
        with tempfile.TemporaryDirectory(prefix="bbskill-") as tmp:
            clone_dir = os.path.join(tmp, "repo")
            if not clone(repo, clone_dir):
                failed.append(repo)
                entries.append({"repo": repo, "status": "clone-failed"})
                print(f"[{repo}] skipping (clone failed)", flush=True)
                continue
            cloned += 1
            license_name = license_hint(clone_dir)
            skill_files = list_skill_files(clone_dir)
            print(f"[{repo}] {len(skill_files)} candidate file(s), license {license_name}", flush=True)
            if not skill_files:
                entries.append({"repo": repo, "status": "no-skill-files", "license": license_name})
            for full_path in skill_files:
                rel_path = os.path.relpath(full_path, clone_dir).replace(os.sep, "/")
                size = os.path.getsize(full_path)
                if size > MAX_BYTES_PER_FILE:
                    skipped += 1
                    entries.append({"repo": repo, "path": rel_path, "status": "skipped", "license": license_name, "bytes": size})
                    print(f"  ! skipped {rel_path} ({size} bytes > cap)", flush=True)
                    continue
                with open(full_path, encoding="utf-8", errors="replace") as handle:
                    body = handle.read()
                digest = content_hash(body)
                name = flat_name(repo, rel_path)
                dest = os.path.join(staging_dir, name)
                if not os.path.realpath(dest).startswith(os.path.realpath(staging_dir) + os.sep):
                    raise RuntimeError(f"refusing to write outside staging: {name}")
                kept = by_hash.get(digest)
                if kept and kept != name:
                    duplicates += 1
                    entries.append({
                        "repo": repo,
                        "path": rel_path,
                        "sha256": digest,
                        "dest": name,
                        "status": "duplicate",
                        "kept": kept,
                        "license": license_name,
                    })
                    print(f"  dup {rel_path} (same as {kept})", flush=True)
                    continue
                if os.path.exists(dest):
                    with open(dest, encoding="utf-8", errors="replace") as handle:
                        old_body = strip_header(handle.read())
                    if old_body == body:
                        present += 1
                        by_hash.setdefault(digest, name)
                        by_name[name] = digest
                        entries.append({
                            "repo": repo,
                            "path": rel_path,
                            "sha256": digest,
                            "dest": name,
                            "status": "present",
                            "license": license_name,
                        })
                        continue
                text = attribute(repo, rel_path, now, license_name, body)
                previous = by_name.get(name)
                if previous and by_hash.get(previous) == name:
                    by_hash.pop(previous, None)
                with open(dest, "w", encoding="utf-8") as handle:
                    handle.write(text)
                written += 1
                by_hash[digest] = name
                by_name[name] = digest
                entries.append({
                    "repo": repo,
                    "path": rel_path,
                    "sha256": digest,
                    "dest": name,
                    "status": "written",
                    "license": license_name,
                })

    if cloned == 0:
        exit_code = 1
        verdict = (
            f"PIPELINE BROKEN: 0 of {len(sources)} skill sources cloned "
            f"({', '.join(failed)}). This is not an empty library."
        )
    else:
        exit_code = 0
        verdict = (
            f"Harvest finished. {written} new/updated, {present} already present, "
            f"{duplicates} duplicates skipped, {skipped} too large, {len(failed)} source failures."
        )
    result = {
        "exit_code": exit_code,
        "written": written,
        "present": present,
        "duplicates": duplicates,
        "skipped": skipped,
        "failed_sources": failed,
        "cloned": cloned,
        "files": entries,
        "verdict": verdict,
    }
    _write_manifest(staging_dir, sources, result)
    print(f"\n{verdict}", flush=True)
    return result


def _write_manifest(staging_dir: str, sources, result: dict) -> None:
    payload = {
        "sources": list(sources),
        "verdict": result["verdict"],
        "written": result["written"],
        "present": result["present"],
        "duplicates": result["duplicates"],
        "skipped": result["skipped"],
        "failed_sources": result["failed_sources"],
        "files": result["files"],
    }
    path = os.path.join(staging_dir, MANIFEST_NAME)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def main() -> int:
    result = harvest_sources(
        SOURCES,
        STAGING_DIR,
        clone_repo,
        datetime.now(timezone.utc).isoformat(),
        ROOT,
    )
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
