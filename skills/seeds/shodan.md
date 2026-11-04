---
# bughive-repro-start
cve: CVE-2019-19781
repro: verified-public
references:
  - source: nvd
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-19781"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    url: "https://support.citrix.com/article/CTX267027"
    gave: "advisory page fetched; no concrete input copied"
  - source: ghsa
    url: "https://github.com/advisories/GHSA-jjcm-f6q3-w5xj"
    gave: "advisory text; no package range"
  - source: cisa-kev
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2021-11-03, dueDate 2022-05-03, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    url: "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/multiple/webapps/47930.txt"
    gave: "public PoC (EDB-47930)"
  - source: poc-in-github
    url: "https://github.com/trustedsec/cve-2019-19781"
    gave: "public PoC repository"
# bughive-repro-end
---

# SKILL: shodan
## Queries
- [ ] "Server: Apache 2.2.3"
- [ ] hostname:"target.com"
- [ ] port:21
- [ ] org:"Target Org"
- [ ] title:"citrix gateway"  (nsroot/nsroot, CVE-2019-19781)
- [ ] http.html:"* The wp-config.php"
- [ ] "MongoDB Server Information" port:27017 -authentication
- [ ] "Set-Cookie: mongo-express=" "200 OK"
- [ ] port:"9200" all:"elastic indices"
- [ ] port:5432 PostgreSQL
- [ ] "220" "230 Login successful." port:21
- [ ] x-jenkins 200
- [ ] kibana content-length:217
- [ ] title:"Kibana" port:"5601"
## Elastic paths
/_cat/indices /_cat/nodes /_cat/health /_mapping /_cat/aliases /_cat/master
## Triage
Unauth Elastic → Critical. Kibana unauth → High. Anonymous FTP → High.

<!-- bughive-repro-start -->
## Steps to reproduce

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: citrix application_delivery_controller_firmware 10.5; citrix application_delivery_controller_firmware 11.1; citrix application_delivery_controller_firmware 12.0. NVD lists 10 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-19781)]
- Weakness: CWE-22. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-19781)]

### Input / trigger
- NVD characterizes the trigger as directory traversal. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-19781)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/multiple/webapps/47930.txt)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as directory traversal. Structured affected range: citrix application_delivery_controller_firmware 10.5. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-19781)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-19781)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/multiple/webapps/47930.txt)]

### Public PoC (if any)
- EDB-47930 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/multiple/webapps/47930.txt
- EDB-47901 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/multiple/webapps/47901.sh
- EDB-47913 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/multiple/webapps/47913.rb
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2019-19781
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/trustedsec/cve-2019-19781
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2019/CVE-2019-19781.json

### What's missing
- (none for verified-public)
<!-- bughive-repro-end -->
