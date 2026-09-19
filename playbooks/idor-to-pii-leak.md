# Playbook: IDOR → PII Leak
1. Confirm IDOR on one object (response diff).
2. Determine id space (seq, uuid, hash).
3. Sample 100 ids; count hits.
4. Estimate total = id_space × hit_rate.
5. STOP before mass extraction. Report sample + estimate.
6. Severity scales with PII sensitivity, count, auth required.
## Evidence
Two-account proof · sample ids+responses · blast radius estimate
