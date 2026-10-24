# SKILL: sca-advisory
## Trigger Conditions
A lockfile or package manifest pins a dependency version.
## Root Cause Pattern
The pinned version falls inside an advisory range (introduced, fixed).
## Recon Checklist
- [ ] package.json, package-lock.json, requirements.txt
## Hunt Methodology
1. Read the pinned version. 2. Ask the OSV database (osv-scanner if installed, otherwise api.osv.dev).
3. Confirm only when the response names an advisory id for that version. A name match without a range is not enough.
## Payload Patterns
None. This is a version check, not an exploit.
## Triage Guidance
Advisory id returned for the pinned version is a confirmed dependency finding.
## Example
lodash 4.17.20 is inside published GHSA ranges fixed in 4.17.21.
