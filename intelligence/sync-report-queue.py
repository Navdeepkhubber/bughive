#!/usr/bin/env python3
"""Queue committed disclosed reports for the running DSH classifier.

The GitHub workflow persists reports in ./reports. DSH's classifier watches a
different, machine-local directory, so this bridge runs before skill scoring.
Only files named h1-<numeric id>.json are accepted; already archived reports
are not queued again.
"""
import json
import os
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = Path(os.environ.get("BUGHIVE_REPORTS_DIR", ROOT / "reports"))
DSH = Path(os.environ.get("BUGHIVE_DSH_DIR", Path.home() / ".dsh"))
QUEUE = DSH / "bounty-queue"
ARCHIVE = DSH / "bounty-archive"
LEARNED = DSH / "skills" / "learned"


def sync():
    counts = {"reports_seen": 0, "queued": 0, "already_processed": 0, "invalid": 0}
    for src in sorted(REPORTS.glob("h1-*.json")):
        match = re.fullmatch(r"h1-(\d+)\.json", src.name)
        if not match:
            continue
        counts["reports_seen"] += 1
        try:
            report = json.loads(src.read_text())
        except (OSError, ValueError):
            counts["invalid"] += 1
            continue
        if str(report.get("h1Id")) != match.group(1):
            counts["invalid"] += 1
            continue
        if (ARCHIVE / src.name).exists() or any(LEARNED.glob(f"h1-*-{match.group(1)}.md")):
            counts["already_processed"] += 1
            continue
        dest = QUEUE / src.name
        if not dest.exists():
            QUEUE.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest)
            counts["queued"] += 1
    return counts


if __name__ == "__main__":
    print(json.dumps(sync()))
