# SKILL: wordpress
## Recon
wpscan --url https://target.com/
wpscan --url ... -e at / -e ap / -e vt --api-token <T> / -e vp --api-token <T>
/wp-json/wp/v2/users
/xmlrpc.php
## Hunt
XMLRPC SSRF: pingback.ping
XMLRPC brute: wp.getUsersBlogs
DoS: /wp-cron.php flood, /wp-admin/load-scripts.php?load=... (5MB/req)
Files: /wp-config.php.bak/.old/.swp/.txt/~, /wp-content/debug.log, /wp-content/uploads/dump.sql, /wp-content/backups/
## Triage
Plugin RCE → Critical. Auth bypass → High. Info leak → Low/Med.
