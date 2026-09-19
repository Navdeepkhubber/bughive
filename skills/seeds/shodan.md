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
