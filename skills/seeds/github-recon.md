# SKILL: github-recon
## Keywords to grep
PASSWORD, PWD, APIKEY, API_KEY, TOKEN, ACCESS_TOKEN, SECRETKEY, CLIENT_SECRET, DB_PASSWORD, ROOT_PASSWORD, JDBC_PASSWORD, JIRA_PASSWORD, MAILGUN_KEY, FIREBASE_KEY, SECRET, @target.com, JENKINS, SSH, FTP, AWS, BUCKET, GITHUB_TOKEN, OAUTH, AUTHORIZATION, LDAP
## Hunt
1. github.com/search?q=target.com&type=code
2. Org repos, user repos, gists, pastes
3. Commit history (removed secrets)
4. Validate: github.com/streaak/keyhacks
5. 2FA bypass: github.com/xYantix/snowdump
## Triage
AWS/DB creds → Critical. Live API key → Med/High.
