# SKILL: graphql
## Introspection
{__schema{types{name fields{name}}}}
query { user(id:1){ id email role } }
{ a:user(id:1){email} b:user(id:2){email} c:user(id:3){email} }
## Vectors
1. Introspect schema
2. Enumerate queries/mutations
3. Test field-level authz
4. Aliases: {a:login(...),b:login(...)}
5. Deep nested query DoS
## Triage
Schema leak → Low. Authz bypass → High/Critical.
