#!/usr/bin/env python3
"""Harvest Cloudflare Radar Zero Wire RSS into unverified skills.

Stores title, link, CVE ids, category tags, pubDate, a short summary derived
from those fields, and the CC BY-NC 4.0 attribution. Does not read or write
item descriptions or content:encoded bodies. Reproduction steps are not
invented: every skill is marked repro: unverified and points at the briefing.
"""

import argparse
import json
import os
import re
import shutil
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FEED_URL = "https://radar.cloudflare.com/security/zero-wire/rss"
DEFAULT_OUT = os.path.join(ROOT, "skills", "cloudflare-zero-wire")
USER_AGENT = "bughive-zero-wire/1.0"
CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")
SLUG_RE = re.compile(r"[^a-z0-9]+")

# Exact Steps-to-reproduce sentence. The link is the briefing, not a proof.
REPRO_PREFIX = "Reproduction: not verified — from Cloudflare Radar Zero Wire brief "
TEARDOWN_NOTE = "Verified reproduction requires a teardown."
ATTRIBUTION = "Source: Cloudflare Radar Zero Wire, CC BY-NC 4.0"


def reproduction_line(link: str) -> str:
    return f"{REPRO_PREFIX}{link}."


def attribution_line(link: str) -> str:
    return f"{ATTRIBUTION} {link}"


def _text(node) -> str:
    if node is None or node.text is None:
        return ""
    return " ".join(node.text.split())


def slug_from_link(link: str, title: str) -> str:
    path = urlparse(link).path.rstrip("/").split("/")[-1]
    raw = path or title or "item"
    slug = SLUG_RE.sub("-", raw.lower()).strip("-")
    return (slug or "item")[:80]


def parse_feed(xml_bytes: bytes) -> list:
    """Parse RSS items. Description and content:encoded are never read."""
    if isinstance(xml_bytes, str):
        xml_bytes = xml_bytes.encode("utf-8")
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise ValueError(f"feed is not XML: {exc}") from exc
    tag = root.tag.split("}")[-1].lower()
    if tag != "rss":
        raise ValueError(f"feed root is {root.tag}, not rss")
    channel = root.find("channel")
    if channel is None:
        raise ValueError("rss feed has no channel")

    items = []
    used = set()
    for node in channel.findall("item"):
        title = _text(node.find("title"))
        link = _text(node.find("link"))
        pub_date = _text(node.find("pubDate"))
        if not title or not link:
            raise ValueError("rss item is missing a title or link")
        cves = []
        tags = []
        for cat in node.findall("category"):
            term = _text(cat)
            if not term:
                continue
            if CVE_RE.match(term):
                if term not in cves:
                    cves.append(term)
                continue
            record = {"term": term}
            domain = (cat.attrib.get("domain") or "").strip()
            if domain:
                record["domain"] = domain
            tags.append(record)
        base = slug_from_link(link, title)
        slug = base
        n = 2
        while slug in used:
            slug = f"{base}-{n}"
            n += 1
        used.add(slug)
        items.append(
            {
                "slug": slug,
                "name": f"zero-wire-{slug}",
                "title": title,
                "link": link,
                "pubDate": pub_date,
                "cves": cves,
                "tags": tags,
            }
        )
    if not items:
        raise ValueError("rss channel has no items")
    return items


def _tag_label(tag: dict) -> str:
    if tag.get("domain"):
        return f"{tag['term']} ({tag['domain']})"
    return tag["term"]


def summary_sentences(item: dict) -> tuple:
    if item["cves"]:
        cve_bit = " covering " + ", ".join(item["cves"])
    else:
        cve_bit = " with no CVE id in the feed categories"
    tag_terms = ", ".join(tag["term"] for tag in item["tags"]) or "none"
    published = item["pubDate"] or "an unknown date"
    first = (
        f"{item['title']} is a Cloudflare Radar Zero Wire briefing{cve_bit}, "
        f"published {published}."
    )
    second = f"Tags: {tag_terms}."
    return first, second


def render_skill(item: dict) -> str:
    first, second = summary_sentences(item)
    cves = ", ".join(item["cves"]) if item["cves"] else "none"
    tags = ", ".join(_tag_label(tag) for tag in item["tags"]) if item["tags"] else "none"
    published = item["pubDate"] or "unknown"
    lines = [
        "---",
        f"name: {item['name']}",
        f"description: {first} {second}",
        "repro: unverified",
        "---",
        "",
        f"# {item['title']}",
        "",
        first,
        second,
        "",
        f"- CVE IDs: {cves}",
        f"- Link: {item['link']}",
        f"- Tags: {tags}",
        f"- Published: {published}",
        "",
        "## Steps to reproduce",
        "",
        reproduction_line(item["link"]),
        "",
        TEARDOWN_NOTE,
        "",
        attribution_line(item["link"]),
        "",
    ]
    return "\n".join(lines)


def render_index(items: list, etag, feed_url: str) -> str:
    payload = {
        "feed": feed_url,
        "etag": etag,
        "items": [
            {
                "slug": item["slug"],
                "name": item["name"],
                "title": item["title"],
                "link": item["link"],
                "pubDate": item["pubDate"],
                "cves": list(item["cves"]),
                "tags": [dict(tag) for tag in item["tags"]],
            }
            for item in items
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def load_index(out_dir: str) -> dict:
    path = os.path.join(out_dir, "index.json")
    if not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    return data if isinstance(data, dict) else {}


def load_etag(out_dir: str):
    etag = load_index(out_dir).get("etag")
    return etag or None


def _write_if_changed(path: str, text: str) -> bool:
    existing = None
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as handle:
            existing = handle.read()
    if existing == text:
        return False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return True


def write_tree(out_dir: str, items: list, etag, feed_url: str) -> bool:
    os.makedirs(out_dir, exist_ok=True)
    changed = False
    keep = set()
    for item in items:
        keep.add(item["slug"])
        dest = os.path.join(out_dir, item["slug"])
        os.makedirs(dest, exist_ok=True)
        if _write_if_changed(os.path.join(dest, "SKILL.md"), render_skill(item)):
            changed = True
    for name in list(os.listdir(out_dir)):
        path = os.path.join(out_dir, name)
        if name == "index.json" or name in keep:
            continue
        if os.path.isdir(path):
            shutil.rmtree(path)
            changed = True
        elif os.path.isfile(path):
            os.remove(path)
            changed = True
    if _write_if_changed(os.path.join(out_dir, "index.json"), render_index(items, etag, feed_url)):
        changed = True
    return changed


def fetch_feed(url: str, etag, opener=None, timeout=60):
    """Single GET. Returns (status, etag, body). 304 yields an empty body."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/rss+xml, application/xml;q=0.9, text/xml;q=0.8",
    }
    req = urllib.request.Request(url, headers=headers)
    if etag:
        req.add_header("If-None-Match", etag)
    open_fn = opener or urllib.request.urlopen
    try:
        with open_fn(req, timeout=timeout) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            header_etag = resp.headers.get("ETag") if resp.headers is not None else None
            body = resp.read()
            return status, header_etag, body
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            header_etag = exc.headers.get("ETag") if exc.headers is not None else None
            return 304, header_etag or etag, b""
        raise


def run(out_dir: str, fixture=None, feed_url=FEED_URL, opener=None) -> dict:
    stored_etag = load_etag(out_dir)
    if fixture:
        with open(fixture, "rb") as handle:
            body = handle.read()
        status = 200
        etag = stored_etag
    else:
        status, etag, body = fetch_feed(feed_url, stored_etag, opener=opener)
        if status == 304:
            return {
                "status": 304,
                "changed": False,
                "items": None,
                "etag": etag,
            }
    items = parse_feed(body)
    changed = write_tree(out_dir, items, etag, feed_url)
    return {
        "status": status,
        "changed": changed,
        "items": len(items),
        "etag": etag,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Harvest Cloudflare Radar Zero Wire RSS into skills.")
    parser.add_argument("--feed", default=FEED_URL, help="RSS URL (one GET)")
    parser.add_argument("--out", default=DEFAULT_OUT, help="Output directory")
    parser.add_argument("--fixture", default=None, help="Read this RSS file instead of the network")
    args = parser.parse_args(argv)
    try:
        result = run(args.out, fixture=args.fixture, feed_url=args.feed)
    except (urllib.error.URLError, ValueError, ET.ParseError, OSError) as exc:
        print(f"harvest-zero-wire: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
