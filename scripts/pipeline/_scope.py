#!/usr/bin/env python3
"""Shared wildcard-aware scope matcher for the bash recon pipeline.

WHY THIS EXISTS
The recon shell scripts used to decide scope with ad-hoc string tests:

    in_scope = [h for h in hosts if h in scope
                or any(h.endswith("." + s) or s.endswith("." + h) for s in scope)]

A wildcard entry such as ``*.synedra.com`` can never satisfy ``endswith``, so a
wildcard-only program scope (which is the norm: ``*.synedra.com``,
``*.synedra.cloud``) filtered EVERY real host out. recon-02 then resolved no DNS
names, recon-03 found no IPs, recon-04 probed nothing -- and the hunt produced an
empty, confident-looking "no findings" result. recon-01 was worse: it classified
in-scope subdomains as *out of scope* via an exact set intersection.

This module mirrors ``plugins/dsh-scope-guard/index.js`` byte-for-byte in
semantics so the shell pipeline and the enforcement tool can never disagree:

    ``*``       matches exactly one DNS label (never crosses a dot)
    ``**``      matches one or more labels
    ``!pattern``exclusion -- evaluated first, exclusion always wins
    ``#``       comment; blank lines ignored
    default     DENY (a host must match an include and no exclude)

Usable as a library (``from _scope import scope_allows``) or as a CLI:

    _scope.py check  <scope-file> <host>
    _scope.py filter <scope-file> [host ...]     # hosts from argv, else stdin
    _scope.py roots  <scope-file>                # concrete (wildcard-free) includes
"""

from __future__ import annotations

import re
import sys

__all__ = [
    "parse_scope",
    "pattern_to_regex",
    "normalize_host",
    "scope_allows",
    "filter_hosts",
    "literal_roots",
    "enum_roots",
]


def parse_scope(text: str):
    """Parse a scope document into (include, exclude) pattern lists.

    Accepts newline- or comma-separated text; ``!`` prefix excludes.

    A ``#`` comment runs to end of LINE, not to the next comma, so comments are
    stripped per line *before* the comma split. Splitting first (the original
    behaviour here and in dsh-scope-guard) promoted the tail of any comment
    containing a comma into a bogus scope pattern -- observed as wildcards like
    ``*.synedra.net plus synedra's`` appearing in an "unresolved patterns" list.
    """
    include: list[str] = []
    exclude: list[str] = []
    for raw_line in str(text or "").split("\n"):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        for raw_entry in line.split(","):
            entry = raw_entry.strip()
            if not entry:
                continue
            entry = re.sub(r"^https?://", "", entry)
            entry = re.sub(r"/.*$", "", entry)
            entry = re.sub(r":\d+$", "", entry)
            if not entry:
                continue
            if entry.startswith("!"):
                value = entry[1:].strip().lower()
                if value:
                    exclude.append(value)
            else:
                include.append(entry.lower())
    # De-duplicate while preserving order (same as [...new Set(...)]).
    return list(dict.fromkeys(include)), list(dict.fromkeys(exclude))


def pattern_to_regex(pattern: str) -> re.Pattern:
    """Translate one scope pattern into an anchored RegExp.

    ``*`` -> one label, ``**`` -> one or more labels.
    """
    p = str(pattern or "").strip().lower().rstrip(".")
    out: list[str] = []
    i = 0
    while i < len(p):
        ch = p[i]
        if ch == "*":
            if i + 1 < len(p) and p[i + 1] == "*":
                out.append(".+")
                i += 2
                continue
            out.append("[^.]+")
        else:
            out.append(re.escape(ch))
        i += 1
    return re.compile("^" + "".join(out) + "$")


def normalize_host(target: str) -> str:
    """Normalise any target form (URL, host:port, IPv6 literal) to a bare host."""
    t = str(target or "").strip().lower()
    scheme_idx = t.find("://")
    if scheme_idx != -1:
        t = t[scheme_idx + 3:]
    at = t.rfind("@")
    if at != -1:
        t = t[at + 1:]
    t = t.split("/")[0].split("?")[0].split("#")[0]
    if t.startswith("["):
        end = t.find("]")
        if end != -1:
            t = t[1:end]
    elif t.count(":") == 1:
        t = t.split(":")[0]
    return t.rstrip(".")


def scope_allows(scope_text: str, host: str):
    """Decide whether ``host`` is in scope for ``scope_text``.

    Returns ``(allowed, reason)`` -- identical decision and reason strings to
    scopeAllows() in dsh-scope-guard.
    """
    target = normalize_host(host)
    if not target:
        return False, "empty target"
    include, exclude = parse_scope(scope_text)
    if not include and not exclude:
        return False, "scope document is empty (default deny)"
    for pat in exclude:
        if pattern_to_regex(pat).match(target):
            return False, f'excluded by pattern "{pat}"'
    for pat in include:
        if pattern_to_regex(pat).match(target):
            return True, f'in scope via "{pat}"'
    return False, "no include pattern matched (default deny)"


def filter_hosts(scope_text: str, hosts):
    """Return (allowed, refused) host lists, de-duplicated and order-stable."""
    allowed: list[str] = []
    refused: list[tuple[str, str]] = []
    for host in hosts:
        h = normalize_host(host)
        if not h:
            continue
        ok, reason = scope_allows(scope_text, h)
        if ok:
            if h not in allowed:
                allowed.append(h)
        else:
            refused.append((h, reason))
    return allowed, refused


def literal_roots(scope_text: str):
    """Concrete (wildcard-free) include patterns -- i.e. real hostnames."""
    include, _ = parse_scope(scope_text)
    return [p for p in include if "*" not in p]


def enum_roots(scope_text: str):
    """Root domains worth *passively enumerating* to resolve a wildcard scope.

    ``*.synedra.com`` -> ``synedra.com``; a scoped wildcard host such as
    ``g-*.0.threema.ch`` yields both ``0.threema.ch`` and the registrable
    ``threema.ch``. Enumeration is passive and every discovered name is still
    re-checked with ``scope_allows`` before it is ever contacted, so asking a
    discovery source for a broad apex is safe -- it can only widen what we
    learn, never what we touch.
    """
    include, _ = parse_scope(scope_text)
    roots: list[str] = []

    def add(value: str) -> None:
        value = value.strip(".").lower()
        if value and value not in roots:
            roots.append(value)

    for pattern in include:
        if "*" not in pattern:
            add(pattern)
            continue
        labels = pattern.split(".")
        wildcard_idx = [i for i, label in enumerate(labels) if "*" in label]
        last_wild = max(wildcard_idx) if wildcard_idx else -1
        rest = labels[last_wild + 1:]
        if rest:
            add(".".join(rest))
        if len(labels) >= 2:
            add(".".join(labels[-2:]))
    return roots


def _read_hosts(argv: list[str]) -> list[str]:
    if argv:
        return [a for a in argv if a.strip()]
    return [line.strip() for line in sys.stdin if line.strip()]


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    mode, scope_file = argv[0], argv[1]
    try:
        scope_text = open(scope_file, encoding="utf-8").read()
    except OSError as exc:
        print(f"cannot read scope file {scope_file}: {exc}", file=sys.stderr)
        return 2

    if mode == "check":
        if len(argv) < 3:
            print("check needs a host", file=sys.stderr)
            return 2
        ok, reason = scope_allows(scope_text, argv[2])
        print(f"{'ALLOW' if ok else 'DENY'} {normalize_host(argv[2])} -- {reason}")
        return 0 if ok else 1

    if mode == "filter":
        allowed, _refused = filter_hosts(scope_text, _read_hosts(argv[2:]))
        for host in allowed:
            print(host)
        return 0

    if mode == "roots":
        for root in literal_roots(scope_text):
            print(root)
        return 0

    if mode == "enum-roots":
        for root in enum_roots(scope_text):
            print(root)
        return 0

    print(f"unknown mode: {mode}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
