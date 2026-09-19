# SKILL: prototype-pollution
## Trigger
Deep-merge/clone/extend functions, recursive JSON/query-string parsing.
## Vectors
1. __proto__.x=y via URL/JSON/form input reaching Object.assign/merge fn
2. constructor.prototype.x=y when __proto__ itself is filtered
3. jQuery.extend(true,..) / lodash _.merge/_.defaultsDeep w/ attacker JSON
4. qs-style parser turning a[__proto__][x]=y into nested objects
5. Node: JSON body deep-merged into config/session -> RCE via
   child_process options pollution, or template-engine option pollution
6. express/hapi middleware merging req.body into shared objects
7. node-config / env-driven config merge accepting user input
## Detecting impact
8. Pollute a trusted flag: isAdmin, debug, disableCsrf
9. Pollute a src/innerHTML sink to chain into XSS
10. Pollute a template-engine option (escape) to chain into SSTI/RCE
## Payloads
{"__proto__":{"isAdmin":true}}
{"constructor":{"prototype":{"isAdmin":true}}}
?a[__proto__][polluted]=yes
## Triage
RCE/authz bypass -> Critical. Pollution w/o clear sink -> Medium.
