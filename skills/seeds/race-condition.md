# SKILL: race-condition
## Trigger Conditions
Single-use coupons, balances, votes, or one-time tokens.
## Root Cause Pattern
Check and update are separate steps, so concurrent requests all pass the check.
## Recon Checklist
- [ ] Redeem, transfer, and apply endpoints
## Hunt Methodology
1. Send the same authorized request many times in parallel.
2. Count successes. One success is the intended behavior. More than one is the bug.
## Payload Patterns
Parallel identical POSTs, no payload mutation.
## Triage Guidance
A second applied state change is medium/high. Repeated identical errors are not.
## Example
Twelve parallel redeems of one coupon; two or more return applied.
