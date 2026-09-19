# SKILL: graphql
## Introspection
{__schema{types{name fields{name}}}}
query { user(id:1){ id email role } }
## Vectors
1. Full introspection -> map every type/field/mutation even if the IDE
   (GraphiQL/Playground) is disabled in prod
2. Alias abuse: {a:login(u:"x",p:"1"),b:login(u:"x",p:"2"),...} batches
   hundreds of guesses behind ONE rate-limited request
3. Batch query abuse: array-of-queries in one POST bypasses per-request
   rate limiting entirely
4. Field-level authz gaps: mutation checks role on top field, nested
   field/connection doesn't re-check
5. IDOR via object id in args: user(id:N), swap N for another user
6. Deep/circular nested query -> resource-exhaustion DoS (no depth limit)
7. Directive abuse (@include/@skip w/ attacker vars) to conditionally
   leak fields normally hidden
8. Injection in a custom scalar/resolver arg (SQLi/NoSQLi if the
   resolver builds a query string from it)
9. Subscriptions often skip the authz the query/mutation path enforces
10. Suggestion-based schema leak even w/ introspection off (error
    "did you mean <fieldname>?")
## Triage
Schema leak -> Low. Alias/batch rate-limit bypass on auth -> High.
Field authz bypass / IDOR -> High/Critical. DoS via nesting -> Medium.
