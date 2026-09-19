# SKILL: recon-methodology
## Triggers
Every hunt, before any vuln class.
## Checklist
- [ ] Subdomains: subfinder, amass, assetfinder, chaos, Sublist3r
- [ ] Live probe: httpx, keep 200/301/302
- [ ] Screenshots: aquatone, gowitness
- [ ] Wayback: web.archive.org/cdx/search/cdx?url=*.target.com/*&collapse=urlkey&output=text&fl=original
- [ ] Filter on: password, secret, token, access, pwd, api, .json, =http, email=, aws, admin, .js, config, dashboard, oauth, internal
- [ ] JS: SecretFinder, linkfinder, subjs, jsluice
- [ ] Google dorks -> google-dorks.md; GitHub -> github-recon.md; Shodan -> shodan.md
- [ ] Storage: site:s3.amazonaws.com, storage.googleapis.com/target
- [ ] Atlassian: target.atlassian.net + /servicedesk/customer/user/signup
- [ ] Arjun/ParamMiner on all forms
## Method
1. Emit a JSON summary per phase, never raw output.
2. Rank targets by: dynamic + authenticated + parameterized + recently changed.
## Triage
Static content -> skip. Dynamic + params -> prime target.
