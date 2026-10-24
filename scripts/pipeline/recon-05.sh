#!/usr/bin/env bash
# Phase 05 — content discovery. Stub used to exit 0 with count:0, which starved
# later param/oneliner phases of URLs. This phase:
#   1. crawls live hosts from phase 04 (katana if present, same-origin link extract always)
#   2. probes a small sensitive-path wordlist (GET only, rate-limited)
#   3. optionally ffuf if installed
# All URLs are scope-filtered. Nothing is written as a finding.
set -euo pipefail
source "$(dirname "$0")/_common.sh"
domain="$1"
hd="$(hunt_dir "$domain")"
out="$hd/recon/05-content-discovery"
script_dir="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$out"

tools_run=()
tools_skipped=()
wordlist="$script_dir/wordlists/sensitive-paths.txt"

python3 - "$out" "$hd" "$script_dir" "$wordlist" <<'PY'
import json, shutil, subprocess, sys, time
from pathlib import Path
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser

sys.path.insert(0, sys.argv[3])
from _scope import scope_allows
from _recon_io import live_urls, merge_endpoints, url_in_scope, cap_items, write_json, host_of
from _batch import apply_bounds, knob_int, tranche_host_set

out, hd, script_dir = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
wordlist = Path(sys.argv[4])
scope_text = (hd / "scope.txt").read_text()
seeds = live_urls(hd)
allowed_hosts = tranche_host_set()
if allowed_hosts is not None:
    seeds = [u for u in seeds if host_of(u) in allowed_hosts]
(out / "seeds.txt").write_text("".join(f"{u}\n" for u in seeds))

tools_run, tools_skipped = [], []
found: list[dict] = []
seen = set()
truncated = False
notes = [
    "GET-only, rate-limited. 2xx/3xx/auth-wall paths are attack-surface, not findings.",
    "URLs also merged into recon/all_endpoints for phases 06/12/15/17.",
]
katana_budget = knob_int("BUGHIVE_KATANA_BUDGET_SECONDS", 900, lo=1)
katana_per_host = knob_int("BUGHIVE_KATANA_PER_HOST_SECONDS", 90, lo=1)
result_cap = knob_int("BUGHIVE_KATANA_RESULT_CAP", 2000, lo=1)
deadline = time.monotonic() + katana_budget


def add(url: str, source: str, status=None):
    url = (url or "").split("#")[0].strip()
    if not url.startswith("http") or url in seen:
        return
    if not url_in_scope(scope_text, url):
        return
    seen.add(url)
    row = {"url": url, "source": source}
    if status is not None:
        row["status"] = status
    found.append(row)


class HrefParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag not in ("a", "link", "script", "form", "iframe"):
            return
        ad = dict(attrs)
        for k in ("href", "src", "action"):
            if ad.get(k):
                self.hrefs.append(ad[k])


def katana_supports(flag: str) -> bool:
    try:
        help_run = subprocess.run(["katana", "-h"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return flag in ((help_run.stdout or "") + (help_run.stderr or ""))


# --- katana ---
# Depth 2 and a per-host rate keep a wide registrable domain from crawling forever.
# The stage wall clock still wins: on expiry the partial URL list is kept.
if shutil.which("katana") and seeds:
    tools_run.append("katana")
    kout = out / "katana.txt"
    cmd = [
        "katana", "-list", str(out / "seeds.txt"), "-silent", "-jc",
        "-d", str(knob_int("BUGHIVE_KATANA_DEPTH", 2, lo=1)),
        "-c", str(knob_int("BUGHIVE_KATANA_CONCURRENCY", 10, lo=1)),
        "-p", str(knob_int("BUGHIVE_KATANA_PARALLELISM", 5, lo=1)),
        "-rl", str(knob_int("BUGHIVE_KATANA_RATE", 100, lo=1)),
        "-timeout", "8", "-o", str(kout),
    ]
    if katana_supports("-hrl"):
        cmd[1:1] = ["-hrl", str(knob_int("BUGHIVE_KATANA_HOST_RATE", 20, lo=1))]
    else:
        notes.append("katana has no -hrl flag; per-host rate left to -rl plus the stage budget")
    crawl_for = min(katana_budget, max(katana_per_host, katana_per_host * len(seeds)))
    if katana_supports("-crawl-duration"):
        cmd.extend(["-crawl-duration", str(crawl_for)])
    elif katana_supports("-ct"):
        cmd.extend(["-ct", str(crawl_for)])
    try:
        subprocess.run(
            cmd,
            timeout=katana_budget,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        truncated = True
        notes.append(f"katana hit the {katana_budget}s wall-clock budget; partial URLs kept")
    except FileNotFoundError:
        pass
    if kout.is_file():
        for line in kout.read_text().splitlines():
            add(line.strip(), "katana")
else:
    tools_skipped.append({"tool": "katana", "reason": "not installed; same-origin HTML extract used"})

# --- same-origin homepage extract (always) ---
tools_run.append("curl-extract")
for seed in seeds[:25]:
    if time.monotonic() >= deadline:
        truncated = True
        notes.append("content-discovery wall-clock budget hit during HTML extract; partial URLs kept")
        break
    try:
        r = subprocess.run(
            ["curl", "-sS", "-L", "-m", "12", "-A", "bh-recon/0.1 (authorized; non-destructive)", seed],
            capture_output=True,
            text=True,
            timeout=16,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        continue
    body = r.stdout or ""
    parser = HrefParser()
    try:
        parser.feed(body[:500_000])
    except Exception:
        continue
    origin = f"{urlparse(seed).scheme}://{urlparse(seed).netloc}"
    for href in parser.hrefs:
        absu = urljoin(seed, href)
        if absu.startswith(origin):
            add(absu, "html-extract")
    time.sleep(0.15)

# --- sensitive-path GET ---
paths = [l.strip() for l in wordlist.read_text().splitlines() if l.strip() and not l.startswith("#")]
tools_run.append("sensitive-paths")
hosts_done = 0
for seed in seeds[:20]:
    if time.monotonic() >= deadline:
        truncated = True
        notes.append("content-discovery wall-clock budget hit during sensitive-path probe; partial URLs kept")
        break
    parsed = urlparse(seed)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    hosts_done += 1
    for path in paths:
        url = origin + path
        try:
            r = subprocess.run(
                ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "-m", "8", "-A", "bh-recon/0.1 (authorized; non-destructive)", url],
                capture_output=True,
                text=True,
                timeout=12,
            )
            code = int((r.stdout or "0").strip() or 0)
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            continue
        if code and code < 400:
            add(url, "sensitive-path", code)
        time.sleep(0.12)

# --- ffuf optional ---
if time.monotonic() >= deadline:
    truncated = True
    tools_skipped.append({"tool": "ffuf", "reason": "stage budget exhausted"})
elif shutil.which("ffuf") and seeds:
    tools_run.append("ffuf")
    ffuf_out = out / "ffuf.json"
    seed = seeds[0].rstrip("/")
    try:
        subprocess.run(
            [
                "ffuf", "-u", seed + "/FUZZ", "-w", str(wordlist),
                "-mc", "200,204,301,302,401,403", "-rate", "15", "-t", "10",
                "-timeout", "8", "-of", "json", "-o", str(ffuf_out), "-s",
            ],
            timeout=180,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    data = {}
    try:
        data = json.loads(ffuf_out.read_text()) if ffuf_out.is_file() else {}
    except json.JSONDecodeError:
        data = {}
    for row in data.get("results") or []:
        add(row.get("url") or "", "ffuf", row.get("status"))
else:
    tools_skipped.append({"tool": "ffuf", "reason": "not installed; curated path probe used instead"})

bounded = apply_bounds(found, result_cap=result_cap)
if bounded["truncated"]:
    truncated = True
    notes.extend(bounded["reasons"])
kept = bounded["results"]
items = cap_items(kept)
merge_endpoints(hd, [i["url"] for i in kept], scope_text)
summary = {
    "phase": "05-content-discovery",
    "domain": hd.name,
    "tools_run": tools_run,
    "tools_skipped": tools_skipped,
    "count": len(kept),
    "count_total": len(found),
    "degraded": bool(truncated),
    "truncated": bool(truncated),
    "tranche_hosts": sorted(allowed_hosts) if allowed_hosts is not None else None,
    "katana_budget_seconds": katana_budget,
    "katana_per_host_seconds": katana_per_host,
    "items": items,
    "notes": notes,
    "output_files": [str(out / "seeds.txt")],
}
write_json(out / "summary.json", summary)
print(json.dumps({
    "phase": "05",
    "count": len(kept),
    "items_in_summary": len(items),
    "degraded": bool(truncated),
    "truncated": bool(truncated),
}))
PY

mark_done "$domain" "recon-05"
