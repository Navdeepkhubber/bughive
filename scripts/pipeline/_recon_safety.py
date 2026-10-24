"""Pure helpers for recon scope-safety and honest truncation.

Imported by recon-03/04/07/09. No network. Detection rules live elsewhere;
these functions only decide what is safe to touch and when a phase must
admit it did not finish.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from _scope import is_public_suffix, registrable_domain

# Extensions recon-07 preserves on disk so the JS analyzer's extname check
# sees them. Extensionless bodies are content-sniffed in cli.mjs.
ASSET_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".html", ".htm", ".json",
}


def is_scannable_public_ip(value: str) -> bool:
    """True only for a global unicast address.

    Private, loopback, link-local, multicast, reserved, documentation and
    shared (CGNAT) space is third-party or internal infrastructure. A named-host
    VDP must not port-scan it.
    """
    import ipaddress

    text = str(value or "").strip().split("%", 1)[0]
    if not text:
        return False
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False
    return bool(addr.is_global)


def httpx_truncated(rc, hosts_probed: int, responses: int) -> bool:
    """True when httpx was killed or returned far too little to call success.

    ``responses << hosts_probed`` is a quarter or less, once the host set is
    large enough that a handful of live sites is not the whole set. A killed
    httpx (timeout exit 124) is truncated even if it happened to write a lot.
    """
    try:
        code = int(rc)
    except (TypeError, ValueError):
        code = None
    if code == 124:
        return True
    probed = int(hosts_probed or 0)
    got = int(responses or 0)
    return probed >= 8 and got * 4 < probed


def normalize_asset_url(url: str) -> str | None:
    """Force https, drop default :80/:443, collapse empty path segments.

    ``http://www.example.ca:80//app.js`` becomes ``https://www.example.ca/app.js``.
    Non-default ports are kept. Returns None when there is no host.
    """
    raw = str(url or "").strip()
    if not raw or "://" not in raw:
        return None
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    netloc = host
    if port and port not in (80, 443):
        netloc = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    path = re.sub(r"/{2,}", "/", parts.path or "/")
    if not path.startswith("/"):
        path = "/" + path
    return urlunsplit(("https", netloc, path, parts.query, ""))


def asset_filename(url: str) -> str:
    """Stable content-addressed name that keeps a known URL extension."""
    path = urlsplit(url).path
    ext = Path(path).suffix.lower()
    digest = hashlib.md5(url.encode("utf-8")).hexdigest()
    if ext in ASSET_EXTENSIONS and re.fullmatch(r"\.[a-z0-9]+", ext):
        return digest + ext
    return digest


def unique_registrable_roots(roots, limit: int = 4) -> tuple[list[str], int]:
    """Collapse enum roots to registrable domains and cap the list.

    Public suffixes are dropped, never returned. The second value is how many
    unique registrable domains existed before the cap.
    """
    unique: list[str] = []
    for root in roots or []:
        reg = registrable_domain(str(root))
        if not reg or is_public_suffix(reg):
            continue
        if reg not in unique:
            unique.append(reg)
    cap = max(1, int(limit or 1))
    return unique[:cap], len(unique)
