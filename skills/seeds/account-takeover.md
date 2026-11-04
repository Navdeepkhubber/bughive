---
# bughive-repro-start
cve: CVE-2020-7245
repro: partial
references:
  - source: nvd
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-7245"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: ghsa
    url: "https://github.com/advisories/GHSA-qrhm-93gw-vg83"
    gave: "advisory text; no package range"
  - source: cisa-kev
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "not in KEV"
  - source: exploitdb
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    url: null
    gave: "404 for master/2020/CVE-2020-7245.json"
# bughive-repro-end
---

# SKILL: account-takeover
## Triggers
Register, forgot-password, email change, login.
## Root cause
Bad identity checks, email normalization, token leaks, weak crypto.
## Vectors
1. Re-register: victim@x, Victim@x, " victim@x ", victim@x%00
2. Email-verify bypass -> 2fa-bypass.md; normalization flaw on profile update
3. Forgot-password -> password-reset-flow.md
4. Login response manipulation; broken session mgmt; OAuth/JWT/SAML misconfig
5. CSRF on email/password change; stored HTMLi steals CSRF token
6. Reflected XSS -> cookie theft; admin bypass: SQLi, strcmp, type juggling
7. Support-portal abuse: fake mailer, ticket hijack
8. SMTP injection on verify; pre-ATO: change email before verifying
9. Broken cookie crypto; access token leaked via GET -> wayback
10. Company-email quirks: mehul@target.com (space), mehul@TARGET.com
11. Trailing/leading-space username collides w/ victim (CVE-2020-7245)
12. HPP on auth params; IDOR on any token; session outlives reset
## Triage
Full ATO -> Critical. Pre-ATO/token leak -> High.

<!-- bughive-repro-start -->
## Steps to reproduce

> Status: `repro: partial` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: ctfd ctfd >= 2.0.0, <= 2.2.2. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-7245)]
- Weakness: CWE-640. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-7245)]

### Input / trigger
- Affected product and an abstract condition are public (take over an arbitrary account). No concrete request or public PoC URL was found, so none is stated here. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-7245)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as take over an arbitrary account. Structured affected range: ctfd ctfd >= 2.0.0, <= 2.2.2. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-7245)]

### How to confirm
- Not possible from public sources beyond the affected-versus-patched range above. No concrete input was published, so none was invented. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-7245)]

### Public PoC (if any)
- None found.

### What's missing
- No public PoC (ExploitDB / PoC-in-GitHub / NVD Exploit-tagged refs / GHSA PoC refs empty).
- No concrete request or payload in the cited advisories. None was invented.
<!-- bughive-repro-end -->
