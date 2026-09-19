# Playbook: Unauth API → Data Leak
1. Confirm endpoint returns data with no auth header.
2. Identify returned schema.
3. Sample minimum (1-2 records).
4. Check pagination → estimate scale.
5. Flag PII / financial / health fields.
6. Report with request + response + scale.
## Evidence
Raw request (no Authorization) · redacted response · field inventory
