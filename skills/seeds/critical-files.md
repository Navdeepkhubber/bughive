---
# bughive-repro-start
cve: null
repro: unverified
# bughive-repro-end
---

# SKILL: critical-files
## Paths to probe
/.git/config
/.env
/.htaccess, .htpasswd
/config.php.bak, /wp-config.php.bak, /wp-config.php~
/credentials.txt
/backup.sql, /dump.sql
/phpinfo.php, /info.php
/server-status, /server-info
/.svn/entries
/.DS_Store
/robots.txt, /sitemap.xml
/phpmyadmin, /pma, /adminer.php
/cgi-bin/
/console
/actuator/env
/swagger-ui.html, /openapi.json
## Triage
DB dump → Critical. .git/config → High. phpinfo → Low.

<!-- bughive-repro-start -->
## Steps to reproduce

> Status: `repro: unverified` — no CVE was resolved for this skill. Nothing below was invented.

### What's missing
- no CVE/target in skill; needs teardown or stays unverified
<!-- bughive-repro-end -->
