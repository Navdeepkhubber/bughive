#!/usr/bin/env python3
"""
HackerOne ingestion — dual mode.

Mode A (REST API, reliable):
  Set H1_API_USERNAME and H1_API_TOKEN env vars.
  Register a token at https://hackerone.com/settings/api_token/edit

Mode B (local dataset):
  Drop HackerOne report JSONs into ./reports/ — anything with the fields
  {h1Id, title, severity, disclosedAt, cwe, reportUrl} works. The fetcher
  moves them into the queue. Use this to seed from a downloaded dataset
  (e.g. h1-brain, or your own export).

Mode C (public scrape, best-effort):
  Tries HackerOne's public endpoints. Currently broken upstream but kept
  as a fallback in case they restore it.
"""
import json
import os
import re
import time
import sys
from pathlib import Path
from datetime import datetime, timezone
import requests

QUEUE_DIR   = Path.home() / ".dsh" / "bounty-queue"
INDEX_FILE  = QUEUE_DIR / ".index.json"
LOCAL_DIR   = Path(__file__).resolve().parent.parent / "reports"
API_BASE    = "https://api.hackerone.com/v1"
GRAPHQL_URL = "https://hackerone.com/graphql"
HTML_URL    = "https://hackerone.com/hacktivity"

BROWSER_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/120.0.0.0 Safari/537.36"),
    "Accept-Language": "en-US,en;q=0.9",
}

# ─── helpers ────────────────────────────────────────────────────────────────
def load_index():
    if INDEX_FILE.exists():
        try:
            return json.loads(INDEX_FILE.read_text())
        except Exception:
            return []
    return []

def save_index(entries):
    INDEX_FILE.parent.mkdir(parents=True, exist_ok=True)
    INDEX_FILE.write_text(json.dumps(entries, indent=2, ensure_ascii=False))

def report_id_from_url(url):
    m = re.search(r"/reports/(\d+)", url or "")
    return m.group(1) if m else None

def queue_one(report):
    """Report dict → queue file. Returns True if written."""
    rid = report.get("h1Id") or report_id_from_url(report.get("reportUrl"))
    if not rid:
        return False
    dest = QUEUE_DIR / f"h1-{rid}.json"
    if dest.exists():
        return False
    QUEUE_DIR.mkdir(parents=True, exist_ok=True)
    item = {
        "h1Id": rid,
        "title": report.get("title"),
        "severity": report.get("severity"),
        "disclosedAt": report.get("disclosedAt") or report.get("disclosed_at"),
        "weakness": report.get("weakness"),
        "cwe": report.get("cwe"),
        "cveIds": report.get("cveIds"),
        "teamHandle": report.get("teamHandle"),
        "teamName": report.get("teamName"),
        "bountyAmount": report.get("bountyAmount"),
        "reportUrl": report.get("reportUrl") or f"https://hackerone.com/reports/{rid}",
        "vulnerabilityInformation": report.get("vulnerabilityInformation"),
        "fetchedAt": datetime.now(timezone.utc).isoformat(),
    }
    dest.write_text(json.dumps(item, indent=2))
    print(f"  queued h1-{rid} [{report.get('severity') or '?'}] {(report.get('title') or '')[:60]}")
    return True

# ─── Mode A: REST API ───────────────────────────────────────────────────────
def fetch_via_api():
    user = os.environ.get("H1_API_USERNAME")
    token = os.environ.get("H1_API_TOKEN")
    if not user or not token:
        return None  # not configured

    print("[fetcher] Mode A: official REST API")
    auth = ("Basic " + __import__("base64")
            .b64encode(f"{user}:{token}".encode()).decode())

    state_file = QUEUE_DIR / ".last-fetch.json"
    since = None
    if state_file.exists():
        try:
            since = json.loads(state_file.read_text()).get("lastDisclosedAt")
        except Exception:
            pass

    written = 0
    newest = since
    for page in range(1, 11):
        params = {
            "filter[severity][]": ["critical", "high", "medium"],
            "filter[disclosed_at][gt]": since or "2020-01-01T00:00:00Z",
            "sort": "-disclosed_at",
            "page[size]": 100,
            "page[number]": page,
        }
        r = requests.get(
            f"{API_BASE}/reports",
            params=params,
            headers={"Authorization": auth, "Accept": "application/json"},
            timeout=30,
        )
        if r.status_code == 429:
            print("[fetcher] 429; sleeping 70s")
            time.sleep(70)
            r = requests.get(f"{API_BASE}/reports", params=params,
                             headers={"Authorization": auth, "Accept": "application/json"},
                             timeout=30)
        if not r.ok:
            print(f"[fetcher] API {r.status_code}: {r.text[:200]}")
            break
        reports = r.json().get("data", [])
        if not reports:
            break
        for rep in reports:
            a = rep.get("attributes", {})
            da = a.get("disclosed_at")
            if da and (not newest or da > newest):
                newest = da
            queue_one({
                "h1Id": rep.get("id"),
                "title": a.get("title"),
                "severity": a.get("severity_rating"),
                "disclosedAt": da,
                "weakness": a.get("weakness"),
                "cwe": a.get("cwe"),
                "bountyAmount": a.get("bounty_awarded_amount"),
                "reportUrl": f"https://hackerone.com/reports/{rep.get('id')}",
                "vulnerabilityInformation": a.get("vulnerability_information"),
            })
            written += 1
        if len(reports) < 100:
            break

    if newest:
        QUEUE_DIR.mkdir(parents=True, exist_ok=True)
        state_file.write_text(json.dumps({"lastDisclosedAt": newest}, indent=2))
    print(f"[fetcher] API done — {written} queued")
    return written

# ─── Mode B: local reports dir ──────────────────────────────────────────────
def fetch_via_local():
    if not LOCAL_DIR.exists():
        return None
    files = list(LOCAL_DIR.glob("*.json"))
    if not files:
        return None
    print(f"[fetcher] Mode B: local reports dir ({len(files)} files)")
    written = 0
    for f in files:
        try:
            report = json.loads(f.read_text())
            if queue_one(report):
                written += 1
        except Exception as e:
            print(f"  skip {f.name}: {e}")
    print(f"[fetcher] local done — {written} queued")
    return written

# ─── Mode C: public scrape (best-effort) ────────────────────────────────────
def fetch_via_public():
    print("[fetcher] Mode C: public GraphQL/HTML (best-effort)")
    session = requests.Session()
    try:
        session.get(HTML_URL, headers=BROWSER_HEADERS, timeout=30)
    except Exception:
        pass

    query = """
    query HacktivitySearchQuery($queryString: String!, $from: Int, $size: Int, $sort: SortInput!) {
      search(index: CompleteHacktivityReportIndex, query_string: $queryString,
             from: $from, size: $size, sort: $sort) {
        total_count
        nodes { ... on HacktivityDocument {
          report { title url disclosed_at }
          severity_rating cwe cve_ids
          team { handle name }
        } }
      }
    }
    """
    payload = {
        "operationName": "HacktivitySearchQuery",
        "variables": {
            "queryString": "disclosed:true",
            "size": 25, "from": 0,
            "sort": {"field": "disclosed_at", "direction": "DESC"},
        },
        "query": query,
    }
    try:
        r = session.post(GRAPHQL_URL,
                         headers={**BROWSER_HEADERS, "Content-Type": "application/json",
                                  "Origin": "https://hackerone.com",
                                  "Referer": "https://hackerone.com/hacktivity"},
                         json=payload, timeout=30)
        if r.status_code >= 500:
            print(f"[fetcher] GraphQL {r.status_code} — endpoint unavailable")
            return 0
        data = r.json()
        nodes = (data.get("data", {}).get("search", {}).get("nodes") or [])
        written = 0
        for n in nodes:
            rep = n.get("report") or {}
            queue_one({
                "title": rep.get("title"),
                "reportUrl": rep.get("url"),
                "disclosedAt": rep.get("disclosed_at"),
                "severity": n.get("severity_rating"),
                "cwe": {"id": n.get("cwe")} if n.get("cwe") else None,
                "teamHandle": (n.get("team") or {}).get("handle"),
                "teamName": (n.get("team") or {}).get("name"),
            })
            written += 1
        print(f"[fetcher] public done — {written} queued")
        return written
    except Exception as e:
        print(f"[fetcher] public failed: {e}")
        return 0

# ─── main ───────────────────────────────────────────────────────────────────
def main():
    QUEUE_DIR.mkdir(parents=True, exist_ok=True)

    for mode in (fetch_via_api, fetch_via_local, fetch_via_public):
        result = mode()
        if result and result > 0:
            return
        if result == 0:
            # tried, nothing new — but mode succeeded; stop here
            return

    print()
    print("No reports ingested. To fix:")
    print()
    print("  Option A — official API token (recommended):")
    print("    1. Go to https://hackerone.com/settings/api_token/edit")
    print("    2. Create a token (label: 'dsh-pipeline')")
    print("    3. export H1_API_USERNAME=<token identifier>")
    print("       export H1_API_TOKEN=<token value>")
    print("    4. Re-run: npm run fetch")
    print()
    print("  Option B — local dataset:")
    print("    1. Put report JSONs in ./reports/")
    print("       Required fields: h1Id, title, severity, reportUrl")
    print("    2. Re-run: npm run fetch")
    print()
    print("  Option C — public scrape:")
    print("    HackerOne's public endpoints are currently broken.")
    print("    Watch https://github.com/zzzteph/bugbounty-monitor for a fix.")
    sys.exit(1)

if __name__ == "__main__":
    main()
