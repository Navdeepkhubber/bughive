<!-- harvested: 0x002132/skills-bugbounty/hunt-aspnet/SKILL.md on 2026-10-23T20:17:14.016795+00:00 -->
<!-- STAGING ONLY -- condense to skills/_schema.md house style, verify the source repo's license, then promote to skills/seeds/ -->

---
name: hunt-aspnet
description: Hunt ASP.NET-specific surface — ViewState deserialization (signed-only vs encrypted), machineKey recovery, dual-parser MAC-bypass anti-pattern, request-validator bypass, trace.axd/elmah.axd disclosure, load-balanced ViewState cross-node failures, SafeControl enumeration via reflection, customErrors mode=Off stack-trace leaks, classic Webforms .aspx/.asmx/.svc surface. Built for ASP.NET Webforms + WCF + SharePoint farms.
sources: github, authorized-engagement
report_count: 1
# bughive-repro-start
cve:
  - CVE-2025-53770
  - CVE-2017-11317
  - CVE-2017-11357
  - CVE-2019-18935
  - CVE-2021-42237
  - CVE-2019-0604
repro: verified-public
references:
  - source: nvd
    id: CVE-2025-53770
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-53770"
    gave: "descriptions, configurations, 3 Exploit-tagged refs"
  - source: vendor
    id: CVE-2025-53770
    url: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53770"
    gave: "advisory page fetched; no concrete input copied"
  - source: ghsa
    id: CVE-2025-53770
    url: "https://github.com/advisories/GHSA-xcrc-8vqv-vc8r"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2025-53770
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2025-07-20, dueDate 2025-07-21, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2025-53770
    url: "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/windows/remote/52405.py"
    gave: "public PoC (EDB-52405)"
  - source: poc-in-github
    id: CVE-2025-53770
    url: "https://github.com/soltanali0/CVE-2025-53770-Exploit"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2017-11317
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2017-11317"
    gave: "descriptions, configurations, 4 Exploit-tagged refs"
  - source: vendor
    id: CVE-2017-11317
    url: "http://www.telerik.com/support/kb/aspnet-ajax/upload-%28async%29/details/unrestricted-file-upload"
    gave: "advisory page fetched; no concrete input copied"
  - source: ghsa
    id: CVE-2017-11317
    url: "https://github.com/advisories/GHSA-9v96-j7x8-6wjv"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2017-11317
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2022-04-11, dueDate 2022-05-02, knownRansomwareCampaignUse=Unknown"
  - source: exploitdb
    id: CVE-2017-11317
    url: "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/aspx/webapps/43874.py"
    gave: "public PoC (EDB-43874)"
  - source: poc-in-github
    id: CVE-2017-11317
    url: "https://github.com/bao7uo/RAU_crypto"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2017-11357
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2017-11357"
    gave: "descriptions, configurations, 2 Exploit-tagged refs"
  - source: vendor
    id: CVE-2017-11357
    url: "http://www.telerik.com/support/kb/aspnet-ajax/upload-%28async%29/details/insecure-direct-object-reference"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2017-11357
    url: "https://github.com/advisories/GHSA-52hx-8455-4qwv"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2017-11357
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2023-01-26, dueDate 2023-02-16, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2017-11357
    url: "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/aspx/webapps/43874.py"
    gave: "public PoC (EDB-43874)"
  - source: poc-in-github
    id: CVE-2017-11357
    url: null
    gave: "404 for master/2017/CVE-2017-11357.json"
  - source: nvd
    id: CVE-2019-18935
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-18935"
    gave: "descriptions, configurations, 8 Exploit-tagged refs"
  - source: vendor
    id: CVE-2019-18935
    url: "https://www.telerik.com/support/kb/aspnet-ajax/details/allows-javascriptserializer-deserialization"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2019-18935
    url: "https://github.com/advisories/GHSA-c655-3j45-33xw"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2019-18935
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2021-11-03, dueDate 2022-05-03, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2019-18935
    url: "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/aspx/webapps/47793.txt"
    gave: "public PoC (EDB-47793)"
  - source: poc-in-github
    id: CVE-2019-18935
    url: "https://github.com/noperator/CVE-2019-18935"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2021-42237
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-42237"
    gave: "descriptions, configurations, 2 Exploit-tagged refs"
  - source: vendor
    id: CVE-2021-42237
    url: "https://support.sitecore.com/kb?id=kb_article_view&sysparm_article=KB1000776"
    gave: "advisory page fetched; no concrete input copied"
  - source: ghsa
    id: CVE-2021-42237
    url: "https://github.com/advisories/GHSA-j3x5-fr4h-9v7v"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2021-42237
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2022-03-25, dueDate 2022-04-15, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2021-42237
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2021-42237
    url: "https://github.com/ItsIgnacioPortal/CVE-2021-42237"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2019-0604
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-0604"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2019-0604
    url: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0604"
    gave: "advisory page fetched; no concrete input copied"
  - source: ghsa
    id: CVE-2019-0604
    url: "https://github.com/advisories/GHSA-6mr5-xh3f-7vqm"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2019-0604
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2021-11-03, dueDate 2022-05-03, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2019-0604
    url: "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/windows/remote/48053.py"
    gave: "public PoC (EDB-48053)"
  - source: poc-in-github
    id: CVE-2019-0604
    url: "https://github.com/linhlhq/CVE-2019-0604"
    gave: "public PoC repository"
# bughive-repro-end
---

## Crown Jewel Targets

ASP.NET deserialization bugs pay among the highest amounts in bug bounty when they reach RCE. Even when patched, the disclosure-tier findings (signed-only ViewState, dual-parser differential, request-validator quirks) reliably pay Low-Medium.

**Highest-value targets:**

- **SharePoint farms** (any version — 2013/2016/2019/SE) — sign-only ViewState + permissive ToolPane.aspx + anonymous FormDigest creates the CVE-2025-53770 ToolShell precondition chain
- **Telerik UI for ASP.NET AJAX** — `Telerik.Web.UI.WebResource.axd` is a documented RCE sink when keys leak (CVE-2017-11317, CVE-2017-11357, CVE-2019-18935)
- **Classic ASP.NET Webforms enterprise apps** — banking portals, dealer portals, HR systems left on .NET Framework 4.x
- **WCF services** (`*.svc?WSDL`) — often forgotten admin endpoints with looser auth than the main app
- **Sitecore CMS** — ViewState + Sitecore-specific deserialization chains (CVE-2021-42237)
- **DotNetNuke (DNN)** — historic ViewState RCE chains
- **Umbraco CMS** — ViewState + custom deserialization sinks

**Asset types that pay most:** internet-reachable ASP.NET Webforms apps > WCF admin services > Telerik-integrated sites > Classic ASP.NET MVC with VSF (very rare)

---

## Attack Surface Signals

**Response headers indicating ASP.NET:**
```
X-AspNet-Version: 4.0.30319          (classic — disclosure on its own)
X-Powered-By: ASP.NET
X-AspNetMvc-Version: 5.2
Server: Microsoft-IIS/10.0
Set-Cookie: ASP.NET_SessionId=...
Set-Cookie: .ASPXAUTH=...            (Forms auth cookie)
Set-Cookie: .ASPXFORMSAUTH=...
Set-Cookie: ASP.NET_SessionId=...; SameSite=None  (suggests cross-origin embedding)
```

**Body signals (in form HTML):**
```
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="..." />
<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="..." />
<input type="hidden" name="__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="" />
                                        ↑ EMPTY = signed-only, not encrypted = exploitable if key leaks
<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="..." />
<input type="hidden" name="__REQUESTDIGEST" id="__REQUESTDIGEST" value="0x...,...">
                                        ↑ SharePoint CSRF token; if anon-issued, see hunt-sharepoint
```

**URL patterns to probe:**
```
/trace.axd                            (per-app trace viewer; sometimes anon-accessible)
/elmah.axd                            (ELMAH error log viewer)
/elmah.axd/?id=...                    (ELMAH RCE / stack-trace leak)
/*.svc                                (WCF services)
/*.svc?wsdl                           (WCF WSDL)
/*.svc/mex                            (Metadata Exchange)
/*.asmx                               (legacy SOAP)
/*.asmx?WSDL                          (legacy SOAP description)
/*.asmx?disco                         (legacy discovery)
/Telerik.Web.UI.WebResource.axd       (Telerik AJAX components)
/ChartImg.axd                         (DataVisualization controls; historic deserialization)
/ScriptResource.axd                   (script resource handler; sometimes leaks paths)
/WebResource.axd                      (web resource handler)
/_vti_bin/*                           (SharePoint Web Service Forwarder)
/api/                                 (Web API 2.x is ASP.NET on classic framework)
/signin                               (often FedAuth / WS-Federation)
```

**Tech-stack signals:**
- `Server: Microsoft-IIS/10.0` (or `/8.5`, `/7.5`) — confirmed Windows + IIS
- `X-AspNet-Version` header — classic .NET Framework (4.x); .NET Core/5+ does NOT emit this
- Cookies with `ASP.NET_SessionId`, `.ASPXAUTH`, `FedAuth` — Forms or claims auth
- `__VIEWSTATE` in form bodies — Webforms (NOT MVC, NOT Razor Pages, NOT Blazor)
- `MicrosoftSharePointTeamServices` header (sometimes stripped by ELB but leaks in `start.aspx` body) — SharePoint

---

## Step-by-Step Hunting Methodology

1. **Fingerprint the framework version.** Trigger any 500 error (stale ViewState POST is a reliable way) and look for `Version Information: Microsoft .NET Framework Version:X.X.XXXXX; ASP.NET Version:X.X.XXXX.X` in the error body. This banner discloses both the runtime and ASP.NET-version-specific patch level. .NET 4.0.30319 + ASP.NET 4.8.x is the most common modern combination.

2. **Locate every form with `__VIEWSTATE`.** Spider the target and grep for `name="__VIEWSTATE"`. Each is a candidate sink for deserialization attacks if MAC / encryption is bypassable.

3. **Check `__VIEWSTATEENCRYPTED` value.** Empty (`value=""`) means ViewState is signed-only via `<machineKey>` but NOT encrypted. Recovery of the validation key → arbitrary deserialization. Non-empty (`value="something"`) means ViewState is BOTH signed and encrypted; both keys needed to forge.

4. **Test the ViewState parser-error differential** (the dual-parser anti-pattern). Send 7+ ViewState shapes and classify responses:
   - Trivial garbage (`AAAA`) → `"Validation of viewstate MAC failed"`
   - Real prefix from current page → `"Validation of viewstate MAC failed"`
   - Flipped-bit real ViewState → `"Validation of viewstate MAC failed"`
   - Oversize (`A * 100000`) → `"Validation of viewstate MAC failed"`
   - XML-shaped (`<xss/>`) → **"The state information is invalid for this page and might be corrupted"** ← different parser path
   - LosFormatter-style prefix (`/wEPDwUKMTcxNzgyOTQwMmRkkz9p4lzA...`) → **"The state information is invalid for this page and might be corrupted"**

   The differential proves there are **two distinct deserialization entry points**, one of which dispatches BEFORE the MAC check on some payload shapes. Historically this enables MAC-before-parse-bypass exploits.

5. **Look for load-balanced cross-node ViewState MAC failures.** If POST gets a 500 with `"Validation of viewstate MAC failed. If this application is hosted by a Web Farm or cluster, ensure that <machineKey> configuration specifies the same validationKey..."`, the farm has multiple WFEs WITHOUT machineKey sync, or without sticky-session affinity. Operationally this breaks legit users; security-wise it confirms farm topology.

6. **Probe `trace.axd` and `elmah.axd`.** If either returns 200 anonymously, it's a Critical finding (trace leaks every request + headers + form data; ELMAH leaks every server error including stack traces).

7. **Enumerate WCF services (`.svc`).** For each, fetch `?wsdl` and `?mex` (metadata exchange). MEX endpoints sometimes return full service contracts including admin operations.

8. **Test request-validator bypass.** ASP.NET's request validator blocks `<` in query strings by default. Bypass categories that may still get through:
   - HTML-entity-encoded payloads (`&lt;script&gt;` — but these don't execute)
   - Encoded inside JSON / XML POST bodies (different content-type ≠ same validator)
   - In path segments (not query) — validator scope depends on framework version
   - In Cookie / Referer headers (varies)
   - Inside `<%@ ... %>` ASP directives if reached via WebDAV PUT (rare)

9. **Check `customErrors` mode.** If 500s expose full stack traces, framework versions, file paths, internal method names → `customErrors mode="Off"` is set. Should be `RemoteOnly` for production.

10. **Look for Telerik components.** `Telerik.Web.UI.WebResource.axd?type=rau` is the historic upload-to-RCE chain (CVE-2017-11317). The `dialogParametersHolder` parameter chain (CVE-2019-18935) requires the encryption key but is otherwise RCE.

11. **SharePoint-specific deserialization paths** — see `hunt-sharepoint` skill for the ToolPane.aspx + anonymous FormDigest + unencrypted ViewState chain.

12. **SafeControl enumeration via reflection.** SharePoint's `Picker.aspx?PickerDialogType=<TypeName>` (and DNN-equivalent endpoints) accept class names and return DIFFERENT error messages for "type exists but not whitelisted" vs "type does not exist." Feed a wordlist of `Microsoft.SharePoint.*.WebControls.*` types to enumerate the SafeControl list — useful for CVE-2019-0604-family hunting.

---

## Payload & Detection Patterns

**Stack-trace fingerprint (trigger via stale ViewState POST):**
```bash
curl -sk -X POST "https://target.example/page.aspx" \
  --data "__VIEWSTATE=AAAA&__VIEWSTATEGENERATOR=AAAA"
# Inspect body for:
#  - "Validation of viewstate MAC failed" → confirms signed ViewState
#  - "The state information is invalid for this page" → confirms ALTERNATE parser path
#  - "Version Information: Microsoft .NET Framework Version:X.X.XXXXX" → exact patch level
#  - "Microsoft.SharePoint.Client.ServerStub..." → SharePoint farm
```

**ViewState parser-error differential probe (Python):**
```python
import requests, re, json
S = requests.Session(); S.verify = False
# Get fresh form
r = S.get("https://target.example/path/page.aspx")
real_vs = re.search(r'__VIEWSTATE" id="__VIEWSTATE" value="([^"]+)', r.text).group(1)
real_vsg = re.search(r'__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="([^"]+)', r.text).group(1)

# Test 7 payload shapes
for label, vs in [
    ("trivial",      "AAAA"),
    ("real",         real_vs),
    ("flipped-bit",  real_vs[:50] + "X" + real_vs[51:]),
    ("oversize",     "A" * 100000),
    ("base64",       "VGVzdE1hcmtlcjY3OFhZWg=="),
    ("xml-shaped",   "<xss/>"),
    ("losformatter", "/wEPDwUKMTcxNzgyOTQwMmRkkz9p4lzA" + "A"*50),
]:
    r = S.post("https://target.example/path/page.aspx",
               data={"__VIEWSTATE": vs, "__VIEWSTATEGENERATOR": real_vsg})
    title = re.search(r'<title>([^<]+)</title>', r.text)
    title = title.group(1)[:100] if title else "—"
    print(f"  [{label:14s}] {r.status_code}  {title}")
```

**`trace.axd` anonymous check:**
```bash
curl -sk -o /dev/null -w "%{http_code}\n" "https://target.example/trace.axd"
# 200 = full trace dump exposed → Critical
# 403 = mod set to localhost-only → check via X-Forwarded-For: 127.0.0.1
```

**WCF service enumeration:**
```bash
# Find all .svc files
curl -sk "https://target.example/" -o body.html
grep -oE '/[a-zA-Z0-9/_-]+\.svc' body.html | sort -u
# For each found:
curl -sk "https://target.example/Service.svc?wsdl" | xmllint --format - | head -60
```

**Request-validator bypass categories:**
```
# Default: <script>alert(1)</script> in ?q= → "Potentially dangerous Request.QueryString value detected"
# Bypasses that sometimes work:
?q=%3cscript%3e            (URL-encoded — depends on validator config)
?q=<svg/onload=alert(1)>  (depends on validator version)
?q=<%00script>             (NUL-byte; older validators)
?q=javascript:alert(1)     (no < at all — passes validator)
Cookie: foo=<script>       (cookie body not validated by default)
Referer: http://x.com/<script>  (referer not validated in classic ASP.NET)
```

**Telerik exploit gate (CVE-2019-18935 — requires encryption keys):**
```bash
# Fingerprint Telerik
curl -sk "https://target.example/Telerik.Web.UI.WebResource.axd?type=rau" -X POST
# If response is RadAsyncUploadHandler-style → Telerik present; try keys
# Public exploits require leaked machineKey AND telerikEncryptionKey
```

---

## Common Root Causes

1. **`viewStateEncryption="Auto"` defaults to signed-only on pages without sensitive ViewState data.** Many SharePoint pages are configured this way. When `__VIEWSTATEENCRYPTED` is empty, ViewState is signed-only — recovery of `validationKey` alone enables forgery.

2. **`<machineKey>` AutoGenerate in a Web Farm.** Each WFE generates a different key on first boot; ViewState issued by one WFE fails MAC validation on another. Operationally produces 500s; security-wise broadcasts the topology (the error message names the cluster).

3. **`<customErrors mode="Off">` left from development.** Stack traces with full method names, file paths, version banners exposed to anonymous internet users.

4. **`trace.axd` / `elmah.axd` left enabled in production.** Often forgotten in `<system.web><trace enabled="true">` blocks.

5. **Forgotten WCF `.svc` admin endpoints.** Built for internal admin tooling, never disabled when the main app went to internet exposure.

6. **Dual-parser anti-pattern: `ObjectStateFormatter` (legacy) vs `LosFormatter` (modern) deserialize in different orders relative to MAC validation.** Some payload shapes hit the legacy parser BEFORE MAC check.

7. **Request validator only applies to URL-encoded body and querystring.** Headers, cookies, XML/JSON bodies, and multipart fields are NOT validated by default. Developers assume validator is universal; it is not.

8. **`<machineKey>` checked into source repos.** Configuration check-ins to GitHub frequently leak validation/decryption keys. Combine with `hunt-misc` source-recon for Telerik / SharePoint / DNN keys.

9. **`SafeControls` web.config entries trusted to gate deserialization.** SharePoint's `<SafeControl>` list determines which classes Picker.aspx can instantiate. Bypasses exist when the inheritance check is the only gate (CVE-2019-0604 family).

---

## Bypass Techniques

| Defense | Bypass |
|---|---|
| `__VIEWSTATEENCRYPTED` non-empty (encrypted) | Recover both decryption + validation keys from any source-code leak / config-disclosure / VS forge primitive; without keys, deserialization cannot be triggered |
| Request validator blocks `<` in querystring | Move payload to Cookie / Referer / JSON body / multipart filename — validator doesn't reach those contexts in classic ASP.NET |
| `EnableViewStateMac="true"` enforced | Recover `validationKey` from web.config disclosure or `<machineKey>` AutoGenerate fingerprinting (ysoserial.net `--minify --islegacy` mode generates ViewState that passes some MAC-validation gaps) |
| `trace.axd` localhost-only | Set `X-Forwarded-For: 127.0.0.1` if the trace mode is `localOnly` and the validation uses Request.UserHostAddress (some apps use Forwarded-For instead) |
| WCF `.svc` 401 on anonymous | Try `?wsdl` and `?mex` first; metadata is sometimes anonymously enumerable even when service ops require auth |
| Telerik upload patched | Check the Telerik version: anything pre-2017Q1 (build 2017.1.118 or earlier) is the original RAU RCE. Check 2017Q3 - 2019Q3 for CVE-2019-18935 |
| `SafeControl` whitelist enforced | Inheritance gate (`instanceof PickerDialog`) IS the gate on patched SP — bypass requires finding a SafeControl subclass with a deserialization sink; enumerate via Picker.aspx |
| `customErrors mode="On"` (no stack traces) | Force a different error path: invalid Content-Length, malformed ViewState that triggers a parser-level exception below the customErrors handler |

---

## Gate 0 Validation

Before writing the report, confirm:

1. **What can the attacker DO right now with the disclosed information?**
   - `trace.axd` 200 with full request dump → **Critical** (PII / session cookies / Authorization headers exposed)
   - `elmah.axd` 200 with error log → **High** (stack traces + internal paths + sometimes credentials)
   - `__VIEWSTATEENCRYPTED` empty + recoverable machineKey via separate finding → **Critical chain to RCE**
   - `__VIEWSTATEENCRYPTED` empty without key recovery → **Low-Medium** (primitive present, not exploitable on its own)
   - Stack traces in 500s → **Low** unless they include credentials / connection strings

2. **Have you reproduced the full chain to attacker-attainable impact, or only the primitive?**
   - Cross-reference `triage-validation` Pre-Severity Gate. "Primitive confirmed" is not Critical until the chain ends in impact.

3. **Can a triager reproduce in <10 min from your report?**
   - Each step copy-pasteable curl / Python.
   - For RCE chains: link the public exploit tool (ysoserial.net, viewgen, telerik-revda) and the specific gadget chain.

---

## Real Impact Examples

### Scenario A — Signed-only ViewState + permissive ToolPane on EoL SharePoint 2013

`https://target-portal.example/_layouts/15/ToolPane.aspx?DisplayMode=Edit` returns 200 anonymously. The form contains `__VIEWSTATE` (signed only — `__VIEWSTATEENCRYPTED=""`), and `__REQUESTDIGEST` is anonymously issued via `_api/contextinfo`. Combined with SP2013 being end-of-life (no patch will ever ship), this is the canonical CVE-2025-53770 "ToolShell" precondition chain on a permanently-unpatched code path. Reported severity: **Critical**. The dual-parser test (Section 4 of Methodology) confirmed that XML-shaped payloads reach the legacy `ObjectStateFormatter` BEFORE MAC validation — additional evidence that the chain is reachable even without full machineKey recovery (though full RCE requires both).

### Scenario B — Telerik RadAsyncUploadHandler exposed on legacy bank portal

`/Telerik.Web.UI.WebResource.axd?type=rau` returns the Telerik upload handler. Telerik version (visible in JS bundle metadata) is 2016.3.1027. CVE-2017-11317 applies — keys are baked into the public Telerik DLL of that version. Upload → write `aspx` to `/app_data/` → request → RCE. Reported severity: **Critical**.

### Scenario C — trace.axd + elmah.axd both exposed on enterprise HR portal

`trace.axd` 200 returns 50 most recent requests, including `Authorization: Bearer eyJ...` headers on API requests. `elmah.axd` 200 returns full error log with database connection-string in one of the exceptions. Reported severity: **Critical** (credentials in plaintext to anonymous internet).

---

## Related Skills & Chains

- **`hunt-rce`** — ViewState deserialization is the headline ASP.NET RCE path; signed-only ViewState + leaked machineKey = RCE every time. Chain primitive: ASP.NET ViewState dual-parser MAC-bypass anti-pattern detected (signed but not encrypted, `<%@ Page enableViewStateMac="true" viewStateEncryptionMode="Never" %>`) + machineKey recovered (from web.config disclosure, `elmah.axd`, source leak, or GitHub) → `hunt-rce` ysoserial.net `TypeConfuseDelegate` gadget → arbitrary command in `w3wp.exe` worker-process identity.
- **`hunt-sharepoint`** — SharePoint farms inherit every ASP.NET anti-pattern plus their own surface. Chain primitive: ASP.NET fingerprint reveals SharePoint (X-SharePoint headers + `/_layouts/` reachable) → pivot to `hunt-sharepoint` for SP-specific RCE paths (ToolShell, SafeControl reflection) before generic ViewState attack.
- **`hunt-ntlm-info`** — IIS sites that advertise NTLM/Negotiate anonymously leak AD topology. Chain primitive: ASP.NET app behind IIS with `WWW-Authenticate: NTLM` → `hunt-ntlm-info` Type-2 challenge capture → internal forest name → cross-reference Entra tenant via `m365-entra-attack` discovery.
- **`hunt-file-upload`** — Telerik RadAsyncUpload, Kentico, Umbraco, and DotNetNuke all have historical upload-handler RCE. Chain primitive: ASP.NET CMS fingerprinted → `hunt-file-upload` bypass matrix against the CMS upload handler → `.aspx` written into web-accessible path → request → RCE under app-pool identity.
- **`triage-validation`** — `trace.axd`/`elmah.axd` disclosure is only Critical when it actually leaks live credentials/tokens; pure stack traces are usually Low. Chain primitive: pull every reported finding through `triage-validation` 7-Question Gate before submission — distinguish "verbose error" (informational) from "live bearer token in error log" (Critical) before writing the report (`redteam-report-template`).

<!-- bughive-repro-start -->
## Steps to reproduce — CVE-2025-53770

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: microsoft sharepoint_server < 16.0.18526.20508; microsoft sharepoint_server 2016; microsoft sharepoint_server 2019. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2025-53770)]
- Weakness: CWE-502. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2025-53770)]

### Input / trigger
- NVD characterizes the trigger as deserialization. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2025-53770)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/windows/remote/52405.py)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as deserialization. Structured affected range: microsoft sharepoint_server < 16.0.18526.20508. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2025-53770)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2025-53770)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/windows/remote/52405.py)]

### Public PoC (if any)
- EDB-52405 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/windows/remote/52405.py
- GHSA-listed: https://www.bleepingcomputer.com/news/microsoft/microsoft-sharepoint-zero-day-exploited-in-rce-attacks-no-patch-available
- GHSA-listed: https://www.cisa.gov/news-events/alerts/2025/07/20/microsoft-releases-guidance-exploitation-sharepoint-vulnerability-cve-2025-53770
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/soltanali0/CVE-2025-53770-Exploit
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2025/CVE-2025-53770.json
- NVD Exploit-tagged reference: https://arstechnica.com/security/2025/07/sharepoint-vulnerability-with-9-8-severity-rating-is-under-exploit-across-the-globe/
- NVD Exploit-tagged reference: https://github.com/kaizensecurity/CVE-2025-53770

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2017-11317

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: telerik ui_for_asp.net_ajax <= 2016.3.1027; telerik ui_for_asp.net_ajax 2017.2.503; telerik ui_for_asp.net_ajax 2017.2.621. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2017-11317)]
- Weakness: CWE-326. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2017-11317)]

### Input / trigger
- NVD characterizes the trigger as arbitrary code. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2017-11317)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/aspx/webapps/43874.py)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as arbitrary code. Structured affected range: telerik ui_for_asp.net_ajax <= 2016.3.1027. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2017-11317)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2017-11317)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/aspx/webapps/43874.py)]

### Public PoC (if any)
- EDB-43874 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/aspx/webapps/43874.py
- GHSA-listed: https://www.exploit-db.com/exploits/43874
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2017-11317
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/bao7uo/RAU_crypto
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2017/CVE-2017-11317.json
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/159653/Telerik-UI-ASP.NET-AJAX-RadAsyncUpload-Deserialization.html
- NVD Exploit-tagged reference: https://www.exploit-db.com/exploits/43874/

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2017-11357

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: progress telerik_ui_for_asp.net_ajax < 2020.1.114. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2017-11357)]
- Weakness: CWE-434. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2017-11357)]

### Input / trigger
- NVD characterizes the trigger as arbitrary code. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2017-11357)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/aspx/webapps/43874.py)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as arbitrary code. Structured affected range: progress telerik_ui_for_asp.net_ajax < 2020.1.114. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2017-11357)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2017-11357)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/aspx/webapps/43874.py)]

### Public PoC (if any)
- EDB-43874 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/aspx/webapps/43874.py
- GHSA-listed: https://www.exploit-db.com/exploits/43874
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2017-11357
- NVD Exploit-tagged reference: https://www.exploit-db.com/exploits/43874/

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2019-18935

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: telerik ui_for_asp.net_ajax >= 2011.1.315, <= 2020.1.114. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-18935)]
- Weakness: CWE-502. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-18935)]

### Input / trigger
- NVD characterizes the trigger as remote code execution. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-18935)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/aspx/webapps/47793.txt)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as remote code execution. Structured affected range: telerik ui_for_asp.net_ajax >= 2011.1.315, <= 2020.1.114. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-18935)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-18935)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/aspx/webapps/47793.txt)]

### Public PoC (if any)
- EDB-47793 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/aspx/webapps/47793.txt
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2019-18935
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/noperator/CVE-2019-18935
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2019/CVE-2019-18935.json
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/159653/Telerik-UI-ASP.NET-AJAX-RadAsyncUpload-Deserialization.html
- NVD Exploit-tagged reference: https://github.com/bao7uo/RAU_crypto

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2021-42237

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: sitecore experience_platform 7.5; sitecore experience_platform 8.0; sitecore experience_platform 8.1. NVD lists 4 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-42237)]
- Weakness: CWE-502. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-42237)]

### Input / trigger
- NVD characterizes the trigger as command execution. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-42237)] [[nvd](https://blog.assetnote.io/2021/11/02/sitecore-rce/)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as command execution. Structured affected range: sitecore experience_platform 7.5. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-42237)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-42237)] [[nvd](https://blog.assetnote.io/2021/11/02/sitecore-rce/)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-42237
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/ItsIgnacioPortal/CVE-2021-42237
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2021/CVE-2021-42237.json
- NVD Exploit-tagged reference: https://blog.assetnote.io/2021/11/02/sitecore-rce/

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2019-0604

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: microsoft sharepoint_enterprise_server 2016; microsoft sharepoint_foundation 2013; microsoft sharepoint_server 2010. NVD lists 4 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-0604)]
- Weakness: CWE-20. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-0604)]

### Input / trigger
- NVD characterizes the trigger as remote code execution. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-0604)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/windows/remote/48053.py)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as remote code execution. Structured affected range: microsoft sharepoint_enterprise_server 2016. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-0604)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-0604)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/windows/remote/48053.py)]

### Public PoC (if any)
- EDB-48053 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/windows/remote/48053.py
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2019-0604
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/linhlhq/CVE-2019-0604
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2019/CVE-2019-0604.json

### What's missing
- (none for verified-public)
<!-- bughive-repro-end -->
