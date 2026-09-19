# Playbook: SSRF → Cloud Metadata
1. Confirm SSRF via collaborator.
2. Probe:
   AWS http://169.254.169.254/latest/meta-data/iam/security-credentials/
   GCP http://metadata.google.internal/computeMetadata/v1/
   Azure http://169.254.169.254/metadata/identity/oauth2/token
3. Retrieve temp credentials.
4. Verify scope with read-only call (do NOT pivot).
5. Report immediately — Critical.
## Evidence
SSRF request · metadata response (redact secrets) · role/scope proof
