"""Knob loader and stage-bound helper shared by the recon shell phases.

Reads scripts/pipeline/data/batch-defaults.json. An environment variable
with the same name replaces the default. No network.
"""
from __future__ import annotations

import json
import os
import shlex
import sys
from pathlib import Path

__all__ = ["defaults", "knob", "knob_int", "apply_bounds", "tranche_host_set"]

_CACHE: dict | None = None


def defaults() -> dict:
    global _CACHE
    if _CACHE is None:
        path = Path(__file__).with_name("data") / "batch-defaults.json"
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = {}
        _CACHE = {k: v for k, v in raw.items() if k != "note"}
    return _CACHE


def knob(name: str, fallback=None):
    if name in os.environ and str(os.environ.get(name, "")) != "":
        return os.environ[name]
    data = defaults()
    if name in data:
        return data[name]
    return fallback


def knob_int(name: str, fallback: int, lo: int | None = None, hi: int | None = None) -> int:
    raw = knob(name, fallback)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = int(fallback)
    if lo is not None:
        value = max(lo, value)
    if hi is not None:
        value = min(hi, value)
    return value


def tranche_host_set() -> set[str] | None:
    """Hosts for the active tranche, or None when this phase is not tranche-scoped.

    Passive stages leave BUGHIVE_TRANCHE_HOSTS unset and therefore see every
    in-scope host. Active stages set it so one root cannot fan out inside a tranche.
    """
    path = str(os.environ.get("BUGHIVE_TRANCHE_HOSTS") or "").strip()
    if not path:
        return None
    file = Path(path)
    if not file.is_file():
        return None
    hosts = set()
    for line in file.read_text(encoding="utf-8", errors="ignore").splitlines():
        host = line.strip().lower().rstrip(".")
        if host:
            hosts.add(host)
    return hosts


def apply_bounds(results, result_cap=None, elapsed_ms=None, budget_ms=None, exit_code=None) -> dict:
    """Keep partial results when a cap or a wall-clock budget hits first.

    Mirrors scripts/pipeline/tranche.mjs applyStageBounds. A raw response
    difference is not a finding; this only decides whether the stage finished.
    """
    rows = list(results or [])
    total = len(rows)
    reasons: list[str] = []
    truncated = False
    try:
        cap = int(result_cap) if result_cap is not None and str(result_cap) != "" else None
    except (TypeError, ValueError):
        cap = None
    if cap is not None and cap >= 0 and total > cap:
        rows = rows[:cap]
        truncated = True
        reasons.append(f"result cap {cap} reached; kept {cap} of {total}")
    timed_out = False
    try:
        timed_out = int(exit_code) == 124
    except (TypeError, ValueError):
        timed_out = False
    over = False
    try:
        budget = float(budget_ms) if budget_ms is not None and str(budget_ms) != "" else None
        elapsed = float(elapsed_ms) if elapsed_ms is not None and str(elapsed_ms) != "" else None
    except (TypeError, ValueError):
        budget, elapsed = None, None
    if budget is not None and budget > 0 and elapsed is not None and elapsed >= budget:
        over = True
    if timed_out or over:
        truncated = True
        if timed_out:
            reasons.append("wall-clock budget expired (exit 124); partial results kept")
        else:
            reasons.append(
                f"wall-clock budget {int(budget)}ms exceeded at {int(elapsed)}ms; partial results kept"
            )
    return {
        "results": rows,
        "count": len(rows),
        "count_total": total,
        "degraded": bool(truncated),
        "truncated": bool(truncated),
        "reasons": reasons,
    }


def _shell_quote(value) -> str:
    return shlex.quote(str(value))


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "exports":
        for key, value in defaults().items():
            current = os.environ.get(key)
            chosen = current if current not in (None, "") else value
            print(f"{key}={_shell_quote(chosen)}")
        return 0
    if len(argv) > 1 and argv[1] == "apply-bounds":
        payload = json.loads(sys.stdin.read() or "{}")
        print(json.dumps(apply_bounds(
            payload.get("results") or [],
            result_cap=payload.get("resultCap"),
            elapsed_ms=payload.get("elapsedMs"),
            budget_ms=payload.get("budgetMs"),
            exit_code=payload.get("exitCode"),
        )))
        return 0
    print("usage: _batch.py exports | apply-bounds", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
