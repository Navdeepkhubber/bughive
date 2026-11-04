import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from email.message import EmailMessage
from xml.etree import ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "zero-wire", "feed.xml")
SCRIPT = os.path.join(ROOT, "scripts", "harvest-zero-wire.py")
CONTENT = "{http://purl.org/rss/1.0/modules/content/}"

SPEC = importlib.util.spec_from_file_location("harvest_zero_wire", SCRIPT)
harvest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harvest)


def feed_bodies(xml_bytes):
    """Description and content:encoded strings. The harvester must not emit these."""
    root = ET.fromstring(xml_bytes)
    blobs = []
    for item in root.find("channel").findall("item"):
        desc = item.find("description")
        if desc is not None and (desc.text or "").strip():
            blobs.append(desc.text.strip())
        encoded = item.find(CONTENT + "encoded")
        if encoded is not None and (encoded.text or "").strip():
            blobs.append(encoded.text.strip())
    return blobs


def windows(blob, size=120, step=200):
    if len(blob) <= size:
        return [blob]
    return [blob[i : i + size] for i in range(0, len(blob) - size + 1, step)]


def tree_text(out_dir):
    chunks = []
    for dirpath, _dirs, files in os.walk(out_dir):
        for name in files:
            path = os.path.join(dirpath, name)
            with open(path, encoding="utf-8") as handle:
                chunks.append(handle.read())
    return "\n".join(chunks)


def snapshot(out_dir):
    found = {}
    for dirpath, _dirs, files in os.walk(out_dir):
        for name in sorted(files):
            path = os.path.join(dirpath, name)
            with open(path, encoding="utf-8") as handle:
                found[os.path.relpath(path, out_dir)] = handle.read()
    return found


class ZeroWireHarvestTests(unittest.TestCase):
    def test_fixture_is_todays_zero_wire_rss(self):
        with open(FIXTURE, "rb") as handle:
            raw = handle.read()
        self.assertIn(b"<rss", raw)
        self.assertIn(b"content:encoded", raw)
        self.assertIn(b"Linux IPv4 TCP use-after-free", raw)
        self.assertGreaterEqual(len(feed_bodies(raw)), 12)

    def test_real_feed_skills_are_unverified_and_omit_bodies(self):
        with open(FIXTURE, "rb") as handle:
            raw = handle.read()
        items = harvest.parse_feed(raw)
        self.assertEqual(len(items), 6)
        allowed_keys = {"slug", "name", "title", "link", "pubDate", "cves", "tags"}
        for item in items:
            self.assertEqual(set(item), allowed_keys)

        with tempfile.TemporaryDirectory() as out:
            result = harvest.run(out, fixture=FIXTURE, feed_url=harvest.FEED_URL)
            self.assertTrue(result["changed"])
            self.assertEqual(result["items"], 6)
            skills = []
            for item in items:
                path = os.path.join(out, item["slug"], "SKILL.md")
                with open(path, encoding="utf-8") as handle:
                    text = handle.read()
                skills.append((item, text))
                frontmatter = text.split("---", 2)[1]
                self.assertIn("\nrepro: unverified\n", frontmatter)
                self.assertIn(f"name: {item['name']}\n", frontmatter)
                self.assertIn("description: ", frontmatter)
                stanza = (
                    "## Steps to reproduce\n\n"
                    + harvest.reproduction_line(item["link"])
                    + "\n\n"
                    + harvest.TEARDOWN_NOTE
                    + "\n"
                )
                self.assertIn(stanza, text)
                self.assertIn(harvest.attribution_line(item["link"]), text)
                self.assertIn(item["title"], text)
                self.assertIn(item["pubDate"], text)
                for cve in item["cves"]:
                    self.assertIn(cve, text)
                for tag in item["tags"]:
                    self.assertIn(tag["term"], text)
                self.assertNotIn("content:encoded", text)
            combined = tree_text(out)
            self.assertNotIn("content:encoded", combined)
            for blob in feed_bodies(raw):
                self.assertNotIn(blob, combined)
                for chunk in windows(blob):
                    self.assertNotIn(chunk, combined, chunk[:80])
            linux = next(item for item in items if item["slug"] == "linux-ipv4-tcp-use-after-free")
            self.assertEqual(linux["cves"], ["CVE-2026-98432"])
            emudhra = next(item for item in items if item["slug"] == "emudhra-certificate-compromise")
            self.assertEqual(emudhra["cves"], [])
            with open(os.path.join(out, "index.json"), encoding="utf-8") as handle:
                index = json.load(handle)
            self.assertEqual(index["feed"], harvest.FEED_URL)
            self.assertEqual([row["slug"] for row in index["items"]], [item["slug"] for item in items])
            self.assertIsNone(index["etag"])

    def test_generated_skills_omit_trimmed_fixture_bodies(self):
        with open(FIXTURE, "rb") as handle:
            bodies = feed_bodies(handle.read())
        self.assertEqual(len(bodies), 12)
        for blob in bodies:
            self.assertIn("fixture body omitted", blob)
        with tempfile.TemporaryDirectory() as out:
            harvest.run(out, fixture=FIXTURE)
            skills = []
            for dirpath, _dirs, files in os.walk(out):
                for name in files:
                    if name != "SKILL.md":
                        continue
                    with open(os.path.join(dirpath, name), encoding="utf-8") as handle:
                        skills.append(handle.read())
            self.assertEqual(len(skills), 6)
            for text in skills:
                self.assertNotIn("fixture body omitted", text)
                for blob in bodies:
                    self.assertNotIn(blob, text)

    def test_second_fixture_run_is_idempotent(self):
        with tempfile.TemporaryDirectory() as out:
            first = harvest.run(out, fixture=FIXTURE)
            snap = snapshot(out)
            second = harvest.run(out, fixture=FIXTURE)
            self.assertTrue(first["changed"])
            self.assertFalse(second["changed"])
            self.assertEqual(second["items"], 6)
            self.assertEqual(snap, snapshot(out))

    def test_canary_encoded_body_is_not_written_anywhere(self):
        xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
<channel>
<item>
<title>Canary Brief</title>
<link>https://radar.cloudflare.com/security/zero-wire/canary-brief</link>
<pubDate>Wed, 04 Nov 2026 00:00:00 GMT</pubDate>
<description>DO_NOT_STORE_DESCRIPTION_CANARY copied briefing prose.</description>
<content:encoded><![CDATA[<p>DO_NOT_STORE_ENCODED_CANARY exploit narrative CVE-2099-99999.</p>]]></content:encoded>
<category>Needs attention</category>
<category>CVE-2026-10001</category>
</item>
</channel>
</rss>
"""
        with tempfile.TemporaryDirectory() as out:
            path = os.path.join(out, "canary.xml")
            with open(path, "wb") as handle:
                handle.write(xml)
            harvest.run(out, fixture=path)
            combined = tree_text(out)
            self.assertNotIn("DO_NOT_STORE_DESCRIPTION_CANARY", combined)
            self.assertNotIn("DO_NOT_STORE_ENCODED_CANARY", combined)
            self.assertNotIn("CVE-2099-99999", combined)
            self.assertNotIn("content:encoded", combined)
            skill = os.path.join(out, "canary-brief", "SKILL.md")
            with open(skill, encoding="utf-8") as handle:
                text = handle.read()
            self.assertIn("\nrepro: unverified\n", text)
            self.assertIn("CVE-2026-10001", text)
            self.assertIn(harvest.reproduction_line("https://radar.cloudflare.com/security/zero-wire/canary-brief"), text)

    def test_not_modified_does_not_touch_the_tree(self):
        seen = {}

        def opener(req, timeout=60):
            seen["header"] = req.get_header("If-none-match")
            headers = EmailMessage()
            headers["ETag"] = '"frozen"'
            raise urllib.error.HTTPError(harvest.FEED_URL, 304, "Not Modified", headers, None)

        with tempfile.TemporaryDirectory() as out:
            index = os.path.join(out, "index.json")
            with open(index, "w", encoding="utf-8") as handle:
                handle.write('{"feed": "x", "etag": "\\"frozen\\"", "items": []}\n')
            marker = os.path.join(out, "keep.txt")
            with open(marker, "w", encoding="utf-8") as handle:
                handle.write("leave me\n")
            before = snapshot(out)
            result = harvest.run(out, opener=opener)
            self.assertEqual(seen["header"], '"frozen"')
            self.assertEqual(result["status"], 304)
            self.assertFalse(result["changed"])
            self.assertEqual(before, snapshot(out))

    def test_non_rss_is_rejected_without_writes(self):
        with tempfile.TemporaryDirectory() as out:
            path = os.path.join(out, "not-rss.xml")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("<html><title>nope</title></html>\n")
            with self.assertRaises(ValueError):
                harvest.run(out, fixture=path)
            self.assertFalse(os.path.exists(os.path.join(out, "index.json")))
            names = set(os.listdir(out))
            self.assertEqual(names, {"not-rss.xml"})

    def test_stale_skill_dir_is_removed(self):
        with tempfile.TemporaryDirectory() as out:
            stale = os.path.join(out, "not-in-feed")
            os.makedirs(stale)
            with open(os.path.join(stale, "SKILL.md"), "w", encoding="utf-8") as handle:
                handle.write("stale\n")
            harvest.run(out, fixture=FIXTURE)
            self.assertFalse(os.path.exists(stale))

    def test_cli_second_run_reports_no_change(self):
        with tempfile.TemporaryDirectory() as out:
            cmd = [sys.executable, SCRIPT, "--fixture", FIXTURE, "--out", out]
            first = subprocess.run(cmd, check=True, capture_output=True, text=True)
            second = subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.assertEqual(json.loads(first.stdout)["changed"], True)
            self.assertEqual(json.loads(second.stdout)["changed"], False)
            self.assertEqual(json.loads(second.stdout)["items"], 6)


if __name__ == "__main__":
    unittest.main()
