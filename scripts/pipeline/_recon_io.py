"""Shared recon I/O: live URLs, scope-safe endpoint merge, capped summaries.

Used by phases 05–10, 13, 15, harvest. Never contacts a host by itself.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from _scope import scope_allows

ITEM_CAP = 200
HOST_CAP = 40


def read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text())
    except Exception:
        return default if default is not None else {}


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2) + "\n")


def host_of(url_or_host: str) -> str:
    raw = (url_or_host or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        return raw.split("/")[0].split(":")[0].lower()
    try:
        return (urlparse(raw).hostname or "").lower()
    except Exception:
        return ""


def url_in_scope(scope_text: str, url: str) -> bool:
    host = host_of(url)
    if not host:
        return False
    ok, _ = scope_allows(scope_text, host)
    return ok


def live_urls(hd: Path) -> list[str]:
    """HTTPS-preferring live URLs from phase 04."""
    summary = read_json(hd / "recon" / "04-http-probe" / "summary.json", {})
    results = summary.get("results") or read_json(hd / "recon" / "04-http-probe" / "http.json", {})
    urls: list[str] = []
    if isinstance(results, dict):
        for rows in results.values():
            for row in rows if isinstance(rows, list) else [rows]:
                if isinstance(row, dict) and str(row.get("url", "")).startswith("http"):
                    urls.append(row["url"].split()[0])
    webapps = hd / "recon" / "webapps"
    if webapps.is_file():
        urls.extend(l.strip() for l in webapps.read_text().splitlines() if l.strip().startswith("http"))
    # Prefer https, unique, stable order
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[: 200]


def merge_endpoints(hd: Path, extra: list[str], scope_text: str | None = None) -> int:
    path = hd / "recon" / "all_endpoints"
    existing = []
    if path.is_file():
        existing = [l.strip() for l in path.read_text().splitlines() if l.strip()]
    if scope_text is None:
        scope_text = (hd / "scope.txt").read_text() if (hd / "scope.txt").is_file() else ""
    seen = set(existing)
    for u in extra:
        u = (u or "").strip()
        if not u.startswith("http"):
            continue
        if u in seen:
            continue
        if scope_text and not url_in_scope(scope_text, u):
            continue
        seen.add(u)
        existing.append(u)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{u}\n" for u in existing))
    return len(existing)


def cap_items(items: list, n: int = ITEM_CAP) -> list:
    return items[:n]


def param_urls_from(text_or_urls: list[str]) -> list[str]:
    out = []
    for u in text_or_urls:
        if "?" in u and "=" in u and u.startswith("http"):
            out.append(u.split()[0])
    return sorted(set(out))


SECRETISH = re.compile(
    r"(api[_-]?key|secret|token|password|authorization|bearer|private[_-]?key)",
    re.I,
)


def redact(value: str, keep: int = 6) -> str:
    v = str(value or "")
    if len(v) <= keep:
        return "***"
    return v[:keep] + "…" + f"(len={len(v)})"
