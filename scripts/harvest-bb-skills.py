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
author, commit, and a short license hint read from the source repo. The hint
is not permission to load the file. `scripts/ingest-staging.mjs` promotes a
house-style skill into skills/learned/ and, when that class has no seed, into
skills/seeds/. This script does not write those directories.
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
PERMISSIVE = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Unlicense"}


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def strip_header(text: str) -> str:
    if text.startswith("<!-- harvested:"):
        return text.split("\n\n", 1)[-1]
    return text


def fetched_stamp(text: str, fallback: str) -> str:
    match = re.search(r"harvested:.*? on (\S+)", text)
    return match.group(1) if match else fallback


def provenance_changed(old_text: str, meta: dict, license_name: str) -> bool:
    """True when a re-clone can fill author, commit, or license without touching the body."""
    header = old_text.split("\n\n", 1)[0]
    if meta.get("author") not in ("", "unknown") and f"author: {meta['author']}" not in header:
        return True
    if meta.get("commit") not in ("", "unknown") and f"commit: {meta['commit']}" not in header:
        return True
    if license_name not in ("", "unspecified") and f"license: {license_name}" not in header:
        return True
    return False


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


def license_policy(name: str) -> str:
    """permissive: stage and allow ingest to copy. flagged: stage for derivation only.
    skip: copyleft, do not write the files into this repo."""
    if name in PERMISSIVE:
        return "permissive"
    token = (name or "").upper()
    if token.startswith("AGPL") or token.startswith("GPL"):
        return "skip"
    return "flagged"


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


def git_meta(repo_dir: str) -> dict:
    def one(*args):
        try:
            done = subprocess.run(
                ["git", "-C", repo_dir, *args],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return (done.stdout or "").strip()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    return {
        "commit": one("rev-parse", "HEAD") or "unknown",
        "author": one("log", "-1", "--format=%an") or "unknown",
    }


def attribute(repo: str, rel_path: str, fetched: str, license_name: str, body: str, author: str = "unknown", commit: str = "unknown") -> str:
    rel = rel_path.replace(os.sep, "/")
    return (
        f"<!-- harvested: {repo}/{rel} on {fetched} -->\n"
        f"<!-- license: {license_name}; author: {author}; commit: {commit}; "
        "source repo license, not permission to load or promote -->\n"
        "<!-- STAGING ONLY -- not loaded. ingest-skills writes a house-style "
        "skill; a permissive license may also keep this text in skills/learned/. -->\n\n"
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
    flagged = []
    license_skipped = []
    cloned = 0

    if not sources:
        result = {
            "exit_code": 2,
            "written": 0,
            "present": 0,
            "duplicates": 0,
            "skipped": 0,
            "failed_sources": [],
            "flagged_sources": [],
            "license_skipped": [],
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
            policy = license_policy(license_name)
            meta = git_meta(clone_dir)
            skill_files = list_skill_files(clone_dir)
            print(f"[{repo}] {len(skill_files)} candidate file(s), license {license_name}", flush=True)
            if policy == "skip":
                license_skipped.append(repo)
                entries.append({
                    "repo": repo,
                    "status": "license-skipped",
                    "license": license_name,
                    "license_policy": "skip",
                })
                print(f"[{repo}] SKIPPED incompatible license {license_name}; no files staged", flush=True)
                continue
            if policy == "flagged":
                flagged.append(repo)
                print(f"[{repo}] FLAGGED license {license_name}; staging for derivation only", flush=True)
            if not skill_files:
                entries.append({"repo": repo, "status": "no-skill-files", "license": license_name, "license_policy": policy})
            for full_path in skill_files:
                rel_path = os.path.relpath(full_path, clone_dir).replace(os.sep, "/")
                size = os.path.getsize(full_path)
                if size > MAX_BYTES_PER_FILE:
                    skipped += 1
                    entries.append({"repo": repo, "path": rel_path, "status": "skipped", "license": license_name, "license_policy": policy, "bytes": size})
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
                        "license_policy": policy,
                    })
                    print(f"  dup {rel_path} (same as {kept})", flush=True)
                    continue
                if os.path.exists(dest):
                    with open(dest, encoding="utf-8", errors="replace") as handle:
                        old_text = handle.read()
                    if strip_header(old_text) == body:
                        present += 1
                        by_hash.setdefault(digest, name)
                        by_name[name] = digest
                        status = "present"
                        fresh = attribute(
                            repo, rel_path, fetched_stamp(old_text, now), license_name, body,
                            meta["author"], meta["commit"],
                        )
                        if fresh != old_text and provenance_changed(old_text, meta, license_name):
                            with open(dest, "w", encoding="utf-8") as handle:
                                handle.write(fresh)
                            status = "provenance"
                        entries.append({
                            "repo": repo,
                            "path": rel_path,
                            "sha256": digest,
                            "dest": name,
                            "status": status,
                            "license": license_name,
                            "license_policy": policy,
                            "author": meta["author"],
                            "commit": meta["commit"],
                        })
                        continue
                text = attribute(repo, rel_path, now, license_name, body, meta["author"], meta["commit"])
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
                    "license_policy": policy,
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
            f"{duplicates} duplicates skipped, {skipped} too large, "
            f"{len(license_skipped)} copyleft repos skipped, {len(flagged)} non-permissive repos flagged, "
            f"{len(failed)} source failures."
        )
    result = {
        "exit_code": exit_code,
        "written": written,
        "present": present,
        "duplicates": duplicates,
        "skipped": skipped,
        "failed_sources": failed,
        "flagged_sources": flagged,
        "license_skipped": license_skipped,
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
        "flagged_sources": result.get("flagged_sources", []),
        "license_skipped": result.get("license_skipped", []),
        "files": result["files"],
    }
    path = os.path.join(staging_dir, MANIFEST_NAME)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def read_sources(path: str) -> list:
    repos = []
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.split("#", 1)[0].strip()
            if line:
                repos.append(line)
    return repos


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    dry = "--dry-run" in args
    source_file = os.path.join(ROOT, "skills", "sources.txt")
    if "--sources" in args:
        source_file = args[args.index("--sources") + 1]
    sources = read_sources(source_file) if os.path.isfile(source_file) else list(SOURCES)
    if dry:
        print(json.dumps({"dry_run": True, "sources": sources}))
        return 0 if sources else 2
    result = harvest_sources(
        sources,
        STAGING_DIR,
        clone_repo,
        datetime.now(timezone.utc).isoformat(),
        ROOT,
    )
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
