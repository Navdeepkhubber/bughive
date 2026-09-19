# SKILL: subdomain-takeover
## Fingerprints
S3: NoSuchBucket
GitHub Pages: "There isn't a GitHub Pages site here"
Heroku: "No such app"
Netlify, Vercel, Azure, Fastly, Shopify: provider-specific
## Hunt
1. Enumerate subdomains, resolve CNAMEs
2. Request each resource
3. Match fingerprints
4. Claim, prove control, report (do NOT abuse)
5. Tools: HostileSubBruteforcer, Can-I-Takeover-XYZ
## Triage
Claimable + cookie-scoped → Critical. Unclaimable → Informational.
