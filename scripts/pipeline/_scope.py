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

import json
import re
import sys
from pathlib import Path

__all__ = [
    "parse_scope",
    "pattern_to_regex",
    "normalize_host",
    "scope_allows",
    "filter_hosts",
    "literal_roots",
    "enum_roots",
    "is_public_suffix",
    "registrable_domain",
]

# Fallback if the shared guard file cannot be read. Kept in sync with
# scripts/pipeline/data/public-suffix-guards.json; the file is the source of truth.
_FALLBACK_RULES = {
    "sld_tokens": ["ac", "co", "com", "edu", "go", "gob", "gov", "govt", "ne", "net", "or", "org"],
    "au_slds": ["edu", "gov"],
    "au_states": ["act", "nsw", "nt", "qld", "sa", "tas", "vic", "wa"],
    "extra_suffixes": ["uk.com", "eu.com"],
}


def _suffix_rules() -> dict:
    path = Path(__file__).with_name("data") / "public-suffix-guards.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        data = _FALLBACK_RULES
    return {
        "sld_tokens": frozenset(str(t).lower() for t in data.get("sld_tokens") or _FALLBACK_RULES["sld_tokens"]),
        "au_slds": frozenset(str(t).lower() for t in data.get("au_slds") or []),
        "au_states": frozenset(str(t).lower() for t in data.get("au_states") or []),
        "extra_suffixes": tuple(
            sorted((str(s).lower().strip(".") for s in data.get("extra_suffixes") or []), key=len, reverse=True)
        ),
    }


_RULES = _suffix_rules()


def _labels(host: str) -> list[str]:
    return [part for part in str(host or "").strip().lower().rstrip(".").split(".") if part]


def suffix_length(labels: list[str]) -> int:
    """How many trailing labels are the public suffix (at least 1 when non-empty)."""
    n = len(labels)
    if n == 0:
        return 0
    joined = ".".join(labels)
    best = 1
    for suf in _RULES["extra_suffixes"]:
        if joined == suf or joined.endswith("." + suf):
            best = max(best, suf.count(".") + 1)
            break
    if (
        n >= 3
        and labels[-1] == "au"
        and labels[-2] in _RULES["au_slds"]
        and labels[-3] in _RULES["au_states"]
    ):
        best = max(best, 3)
    if n >= 2 and len(labels[-1]) == 2 and labels[-2] in _RULES["sld_tokens"]:
        best = max(best, 2)
    return best


def is_public_suffix(host: str) -> bool:
    """True for a TLD or multi-part public suffix (co.jp, com.au, co.nz, co.uk).

    A name with a private label (airnewzealand.co.jp) is not a public suffix.
    Wildcard patterns are not suffixes.
    """
    labels = _labels(host)
    if not labels or any("*" in label for label in labels):
        return False
    if len(labels) == 1:
        return True
    return len(labels) <= suffix_length(labels)


def registrable_domain(host: str) -> str | None:
    """eTLD+1, or None when ``host`` is itself a public suffix or a wildcard."""
    labels = _labels(host)
    if not labels or any("*" in label for label in labels):
        return None
    sl = suffix_length(labels)
    if len(labels) <= sl:
        return None
    return ".".join(labels[-(sl + 1):])


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
    ``threema.ch``. The private-label remainder is preferred. The registrable
    apex is added only when it is not a public suffix.

    ``**.www.airnewzealand.co.jp`` must yield ``www.airnewzealand.co.jp`` (and
    the safe apex ``airnewzealand.co.jp``), never ``co.jp``. Bare public
    suffixes are third-party namespace, not program scope. Enumeration is
    still passive: every discovered name is re-checked with ``scope_allows``
    before it is contacted.
    """
    include, _ = parse_scope(scope_text)
    roots: list[str] = []

    def add(value: str) -> None:
        value = value.strip(".").lower()
        if not value or "*" in value or value in roots:
            return
        if is_public_suffix(value):
            return
        roots.append(value)

    for pattern in include:
        if "*" not in pattern:
            # Literal includes are roots as written. A literal public suffix
            # is still refused — there is no private label to enumerate.
            add(pattern)
            continue
        labels = [part for part in pattern.split(".") if part]
        wildcard_idx = [i for i, label in enumerate(labels) if "*" in label]
        last_wild = max(wildcard_idx) if wildcard_idx else -1
        rest = labels[last_wild + 1:]
        rest_name = ".".join(rest)
        if rest and not is_public_suffix(rest_name):
            add(rest_name)
            reg = registrable_domain(rest_name)
            if reg:
                add(reg)
            continue
        # Remainder was empty or itself a public suffix. Fall back to the
        # registrable apex of whatever private labels the pattern still has.
        bare = [label for label in labels if "*" not in label]
        reg = registrable_domain(".".join(bare)) if bare else None
        if reg:
            add(reg)
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
