# Playbook: XSS → Account Takeover
## Preconditions
Stored/reflected XSS on privileged surface · cookie not HttpOnly OR CSRF readable · admin visits page
## Steps
1. Confirm XSS in victim context.
2. Read CSRF/session from DOM.
3. Exfil to in-scope endpoint.
4. Replay session / privileged action.
5. Document chain.
## Evidence
Exfil screenshot · replayed privileged request/response · chain narrative
## Severity
Lone XSS Medium · XSS→ATO Critical
