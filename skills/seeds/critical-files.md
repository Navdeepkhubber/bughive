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
