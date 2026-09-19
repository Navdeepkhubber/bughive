---
name: mariadb-myisam-keyseg-bof
description: Hunt Classic Buffer Overflow in MariaDB/MySQL MyISAM .MYI index files via uncontrolled keyseg->start / keyseg->length. Use for file-format parser memory-safety audits (MyISAM, table/index file loaders, storage engines).
---

# MyISAM keyseg Buffer Overflow

## 1 Trigger Conditions
- Target loads/repairs a MyISAM table: `myisamchk`, `myisam_repair`, `CHECK/REPAIR TABLE`, `myisampack`, server opening `.MYI` on startup.
- Attacker controls the `.MYI` file: shared hosting, restored backup/tarball, plugin-imported table, object-storage/volume write, MySQL→MariaDB migration path.
- MariaDB/MySQL build without `myisam` hardening and low-privilege user can write into the datadir.

## 2 Root Cause Pattern
`MI_KEYSEG` records read from the on-disk index header carry `start` and `length`. The merge/repair path copies key data with `memcpy(dst + keyseg->start, src + keyseg->start, keyseg->length)` — or sizes a fixed stack array by a count rather than validating `start+length` against `keyinfo->keylength` and the source/destination buffer bounds. No `start <= keylength` and `start+length <= keylength` check ⇒ stack/heap overflow. Classic pattern: **on-disk offset+length field trusted without range validation, used in arithmetic before the bounds check.**

## 3 Recon Checklist
- Identify storage engines in use: `SHOW ENGINES`, `SHOW TABLE STATUS`, look for `.MYI`/`.MYD` in `@@datadir`.
- Version: `SELECT VERSION()`; check MyISAM changelogs for `myisam`/`keyseg` fixes.
- Who can write to datadir: shared hosting, backup import, `SELECT ... INTO OUTFILE` + `LOAD DATA`, filesystem plugins.
- Grep source: `grep -rn "keyseg" storage/myisam/ | grep -E "memcpy|start|length"`; audit `mi_open.c`, `mi_repair.c`/`myisamchk.c`, `mi_check.c`, `mi_pack.c`.
- Build check: is the target compiled with stack protector/ASLR disabled (common in distro `myisamchk` binaries)?

## 4 Hunt Methodology
1. Acquire/build a valid `.MYI` (create table `ENGINE=MyISAM`, insert rows, `FLUSH TABLES`).
2. Parse the header: keydef block (`MI_KEYDEF`: `keysegs`, `keylength`), then `MI_KEYSEG[]` entries (`type, flag, start, length` — mind byte order/`uint16`).
3. Fuzz `keyseg->start`/`keyseg->length`: first large-but-valid, then `start > keylength`, `length=0xFFFF`, `start+length` wrap near `0xFFFF`.
4. Run under ASan/UBSan: `myisamchk --recover t.MYI`, `REPAIR TABLE`, server startup with the table present.
5. Confirm crash address is stack (protector smash) vs heap; capture RIP/saved return for exploitability.
6. Escalate to RCE/DoS: overwrite return address or crash the daemon (unauthenticated if file write is pre-auth, e.g. snapshot/hosted restore).

## 5 Payload Patterns
- `.MYI` layout: `[header][state][base][keydef][keyseg*][recinfo]`; patch `keysegs` to 1 and set `start`/`length` malicious.
- Variants: `start = keylength + 0x100`, `length = 0xFFF0`, `start = 0xFFFF, length = 0xFFFF` (overflow in `start+length`).
- Also fuzz `recinfo`/`MI_COLUMNDEF` offsets for the same trust pattern.
- Minimal PoC: python `struct.pack('<HH', start, length)` written at the keyseg offset, then invoke repair.

## 6 WAF Bypass Tips
WAFs are irrelevant here (binary file upload, not HTTP). Bypass applies to the delivery vector:
- Frame `.MYI` as a backup/`application/octet-stream` upload; zip/gzip it to evade extension + content filters.
- Rename `.MYI`→`.dat`/`.bin`; set table name/path via `CREATE TABLE ... DATA DIRECTORY`.
- Use SQL-level repair (`REPAIR TABLE`) to avoid touching `myisamchk` paths a hardened workflow blocks.
- If upload validation uses magic bytes, note MyISAM headers (`\xFE\xFE\x07\x01`) may pass as generic binary.

## 7 Triage Guidance
- Reproduce with a deterministic harness: baseline valid `.MYI` (no crash) vs probe patched file (ASan abort/segfault) — diff must be attributable solely to `start`/`length`.
- Real only with a stack trace naming the memcpy/copy site plus the malformed field values; a bare "restore failed" is not a finding.
- Severity: RCE on file-write = High/Critical; unauthenticated remote DoS via startup scan = Medium/High; local-only = Low.
- Reject: crash with `start+length` within bounds, integer-overflow flagged by UBSan but no memory corruption, or debug-build-only asserts.
- Report needs: affected versions, exact offsets, crash log, ASan output, and the write primitive (who can plant the file).

## 8 Example
Craft `t.MYI` where `MI_KEYDEF.keysegs=1` and the sole `MI_KEYSEG.length=0xFFF0` with `start=0x8000` while `keylength=64`. Run `myisamchk --recover t.MYI` under ASan → `memcpy` in `_mi_put_key_in_buff` writes past the stack key buffer; stack-smashing detected. If an unprivileged user (or restored backup path) can place the file, escalate to daemon RCE.
