# SKILL: recon-methodology
## Trigger Conditions
Every hunt, before any vuln class.
## Recon Checklist
- [ ] Subdomain enum: subfinder, amass, assetfinder, chaos, Sublist3r
- [ ] Live probe: httpx (keep 200/301/302)
- [ ] Screenshots: aquatone, gowitness
- [ ] WaybackURL: https://web.archive.org/cdx/search/cdx?url=*.target.com/*&collapse=urlkey&output=text&fl=original
- [ ] Filter: password, secret, token, access, pwd, api, .json, =http, =%2F, =/, email=, ey, aws, admin, .js, config, dashboard, oauth, internal
- [ ] JS: SecretFinder, linkfinder, subjs, jsluice
- [ ] Google dorks (google-dorks.md)
- [ ] GitHub recon (github-recon.md)
- [ ] Shodan (shodan.md)
- [ ] Storage: target site:s3.amazonaws.com, storage.googleapis.com/target
- [ ] Atlassian: target.atlassian.net + /servicedesk/customer/user/signup
- [ ] Arjun/ParamMiner on all forms
## Hunt Methodology
1. Emit JSON summary per phase (never raw).
2. Rank: dynamic + auth + params + recent changes.
## Triage
Static → skip. Dynamic + params → prime target.
