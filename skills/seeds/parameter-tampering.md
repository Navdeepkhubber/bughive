# SKILL: parameter-tampering
## Payloads
price=1&currency=INR&quantity=1
price=2999&currency=UZS&quantity=1
price=2000&quantity=0.001
## Vectors
1. Price manipulation: price=1
2. Fractional quantity: 2000×0.001=2
3. Currency swap: 2999 INR → 21 INR
4. Coupon abuse: race, reuse
5. Referral chain: /refer/CODE, wayback 1000 codes, temp emails
6. Free premium via account delete + reuse code
## Triage
Financial loss → Critical. Free premium → High.
