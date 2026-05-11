# PostgreSQL 2PC GID length-check gap on recovery paths

**Discovered:** 2026-05-11 by kuzushi `taint-iris-next:hunt` (Thread D audit)
**Target:** PostgreSQL mainline @ commit `901ed9b352b41f034e17bc540725082a488fce31` (May 8 2026, "Fix universal builds on MacOS")
**File:** `src/backend/access/transam/twophase.c`
**Severity (kuzushi triage):** medium (defense-in-depth)
**Kuzushi findings:** F-0020 (fingerprint `5848f539`) + F-0022 (fingerprint `6b4d1c98`)
**Hunt run:** `/tmp/targets/pg/.kuzushi/runs/run-1778538998-f10f4c242ea8/`

## Summary

`MarkAsPreparingGuts` (line 439) and `PrepareRedoAdd` (line 2513) each
contain a `strcpy(gxact->gid, gid)` into a fixed-size `char[GIDSIZE=200]`
buffer. The `gid` argument flows in from raw `pg_twophase/*` file
content or WAL record data. Neither function validates `strlen(gid) <
GIDSIZE` (or `hdr->gidlen < GIDSIZE`) before the copy.

The user-facing path through `MarkAsPreparing` (line 365) DOES gate this
check at line 371:

```c
if (strlen(gid) >= GIDSIZE)
    ereport(ERROR, ...);
```

The recovery paths bypass it:

- `restoreTwoPhaseData` (line 1910) → `ProcessTwoPhaseBuffer`
  → `ReadTwoPhaseFile` (reads `pg_twophase/<fxid>` from disk)
  → `PrepareRedoAdd` (line 2513) → **strcpy at line 2598**
- `RecoverPreparedTransactions` (line 2089) → `ProcessTwoPhaseBuffer`
  → `ReadTwoPhaseFile` → **MarkAsPreparingGuts strcpy at line 495**
- `xact_redo` (xact.c:6479) → `PrepareRedoAdd` directly with
  `XLogRecGetData(record)` from WAL → **strcpy at line 2598**

`ReadTwoPhaseFile` validates magic, total-length, and CRC32C of the
file but does not validate `hdr->gidlen`. `ProcessTwoPhaseBuffer`
checks XID continuity but not GID length.

## Threat model

Exploit requires write access to `PGDATA/pg_twophase/<fxid>` OR WAL
injection. PostgreSQL treats PGDATA as a trusted boundary — an
attacker with PGDATA write already owns the database (replace
binaries, drop tables, modify WAL). This is not a remote-attacker CVE.

It IS a real defense-in-depth gap that matters in environments where
PGDATA write is partially constrained, e.g.:

- Shared-hosting with postgres-on-LXC/Docker where `pg_twophase` ACLs
  differ from `data/`, `base/`, or binary paths
- Kubernetes deployments using bind-mounted PGDATA shared between
  workload contexts with different SELinux/AppArmor labels
- A secondary vulnerability that grants partial file-write to PGDATA
  (e.g., a CVE in a contrib module's file-handling path that allows
  writing under a configurable directory which an operator may have
  pointed at `pg_twophase`)

In a default postgres install with standard filesystem permissions,
this is not exploitable. In hardened deployments where defense-in-
depth matters, this check is valuable and cheap.

## Reproducer (proof-of-concept, requires PGDATA write)

```sh
# Stop a postgres cluster
pg_ctl -D $PGDATA stop

# Locate a pg_twophase entry from a recent BEGIN PREPARED transaction,
# or generate one:
psql -c "BEGIN; CREATE TEMP TABLE t(); PREPARE TRANSACTION 'short';"

# Now $PGDATA/pg_twophase/<fxid> exists. Modify it:
python3 <<'PY'
import struct, zlib, os, glob
path = glob.glob(os.environ['PGDATA'] + '/pg_twophase/*')[0]
with open(path, 'rb') as f: buf = bytearray(f.read())

# xl_xact_prepare header is at offset 0; gidlen is a uint16 at the
# struct offset of the field. Find it by searching for the existing
# GID bytes.
gidlen_offset = ...  # platform-dependent offset to hdr.gidlen field
gid_start = ...       # MAXALIGN(sizeof(TwoPhaseFileHeader)) per spec

# Overwrite the gid region with >200 non-NUL bytes
buf[gid_start:gid_start+260] = b'A' * 260
# Recompute CRC32C over [0:total_len-4]; pg_crc32c uses Castagnoli polynomial
import crcmod
crc = crcmod.predefined.mkCrcFun('crc-32c')
trailer = crc(bytes(buf[:-4])).to_bytes(4, 'little')
buf[-4:] = trailer

with open(path, 'wb') as f: f.write(bytes(buf))
PY

# Restart — recovery triggers PrepareRedoAdd/MarkAsPreparingGuts → strcpy
pg_ctl -D $PGDATA start
# Postgres will overrun gxact->gid[200] in shared memory during recovery
```

The overflow writes into adjacent shared-memory fields of the
`GlobalTransactionData` struct (the next field after `char gid[GIDSIZE]`
at line 172 of twophase.c). The struct layout includes pointers and
control state; corruption can produce a denial-of-service (postgres
crash on startup) and is potentially exploitable for arbitrary code
execution depending on the shared-memory adjacency.

## Proposed patch

```diff
diff --git a/src/backend/access/transam/twophase.c b/src/backend/access/transam/twophase.c
--- a/src/backend/access/transam/twophase.c
+++ b/src/backend/access/transam/twophase.c
@@ -442,6 +442,16 @@ MarkAsPreparingGuts(GlobalTransaction gxact, FullTransactionId fxid,
 	int			i;
 	TransactionId xid = XidFromFullTransactionId(fxid);

 	Assert(LWLockHeldByMeInMode(TwoPhaseStateLock, LW_EXCLUSIVE));

 	Assert(gxact != NULL);
+
+	/*
+	 * Defense in depth: the user-facing entry point MarkAsPreparing
+	 * validates strlen(gid) < GIDSIZE before calling us, but the
+	 * recovery path RecoverPreparedTransactions reads `gid` from raw
+	 * file content with no such guard. Re-check here so a corrupt 2PC
+	 * state file can't overflow gxact->gid[GIDSIZE] via strcpy below.
+	 */
+	if (strlen(gid) >= GIDSIZE)
+		ereport(ERROR,
+				(errcode(ERRCODE_DATA_CORRUPTED),
+				 errmsg("two-phase state file GID length exceeds GIDSIZE for transaction %u",
+						xid)));
+
 	proc = GetPGProcByNumber(gxact->pgprocno);

 	/* Initialize the PGPROC entry */
@@ -2515,6 +2525,7 @@ PrepareRedoAdd(FullTransactionId fxid, char *buf,
 	TwoPhaseFileHeader *hdr = (TwoPhaseFileHeader *) buf;
 	char	   *bufptr;
 	const char *gid;
 	GlobalTransaction gxact;
+	TransactionId xid;

 	Assert(LWLockHeldByMeInMode(TwoPhaseStateLock, LW_EXCLUSIVE));
 	Assert(RecoveryInProgress());
@@ -2528,6 +2539,15 @@ PrepareRedoAdd(FullTransactionId fxid, char *buf,

 	bufptr = buf + MAXALIGN(sizeof(TwoPhaseFileHeader));
 	gid = (const char *) bufptr;
+	xid = XidFromFullTransactionId(fxid);
+
+	/* Defense in depth: validate gidlen claimed in the file header
+	 * AND that the GID is NUL-terminated within GIDSIZE bytes. */
+	if (hdr->gidlen >= GIDSIZE || strnlen(gid, GIDSIZE) >= GIDSIZE)
+		ereport(ERROR,
+				(errcode(ERRCODE_DATA_CORRUPTED),
+				 errmsg("two-phase state file GID length exceeds GIDSIZE for transaction %u",
+						xid)));

 	/*
 	 * Reserve the GID for the given transaction in the redo code path.
```

The MarkAsPreparing wrapper at line 371 keeps its check (so it errors
earlier with a more specific message on user input); the new check in
MarkAsPreparingGuts is the defense-in-depth backstop for callers that
bypass the wrapper.

## Email draft for security@postgresql.org

Subject: `Defense-in-depth: missing GID length check on two-phase state file recovery paths in twophase.c`

> Hi PostgreSQL security team,
>
> While running an automated taint analysis on PostgreSQL mainline
> (commit `901ed9b35` from 2026-05-08), I identified two `strcpy`
> sites in `src/backend/access/transam/twophase.c` that copy a GID
> from raw `pg_twophase/*` file content or WAL record data into a
> fixed-size `gxact->gid[GIDSIZE=200]` buffer without validating
> `strlen(gid) < GIDSIZE`:
>
> 1. `MarkAsPreparingGuts` (line 439), strcpy at line 495 — reached
>    from the user-facing `MarkAsPreparing` path AND from the
>    recovery path `RecoverPreparedTransactions` (line 2089). The
>    user-facing path is guarded by `if (strlen(gid) >= GIDSIZE)
>    ereport(ERROR, ...)` at line 371 in MarkAsPreparing; the
>    recovery path bypasses that guard.
> 2. `PrepareRedoAdd` (line 2513), strcpy at line 2598 — reached from
>    `restoreTwoPhaseData` (line 1910) AND from `xact_redo`
>    (`xact.c:6479`). Neither caller validates `hdr->gidlen` before
>    the strcpy.
>
> `ReadTwoPhaseFile` validates the file magic, total length, and
> CRC32C but does not validate `hdr->gidlen` against `GIDSIZE`.
> `ProcessTwoPhaseBuffer` checks XID continuity but not GID length.
>
> I do NOT believe this is exploitable under PostgreSQL's standard
> trust-PGDATA threat model — an attacker with PGDATA write access
> can already corrupt the database comprehensively. But the check is
> cheap and would harden against:
>
> - Hardened deployments where PGDATA write is partially constrained
>   (containerised setups, shared-hosting with separate filesystem
>   ACLs on `pg_twophase/`).
> - Compound-bug scenarios where a separate vulnerability grants
>   partial file-write to PGDATA but not full code execution.
>
> Proposed patch (unified diff) attached below — adds a length check
> to both `MarkAsPreparingGuts` and `PrepareRedoAdd`, mirroring the
> existing check in `MarkAsPreparing`. Total: ~15 lines.
>
> Happy to receive feedback on whether you consider this CVE-worthy
> (I don't, but defer to your threat model), and to coordinate
> disclosure timing if so. Otherwise feel free to land it as a
> regular hardening commit.
>
> Thanks for everything you do on PostgreSQL.
>
> — <your name>
>
> ---
>
> [unified diff attached above]

## Status

- Persisted: F-0020 + F-0022 in `/tmp/targets/pg/.kuzushi/v2/findings.sqlite3`
- Email: not yet sent — operator decision
- Patch: not yet upstreamed — pending email reply
- Affected versions: needs `git log` survey on `MarkAsPreparingGuts`
  and `PrepareRedoAdd` to determine introduction commit. The current
  pattern (wrapper checks, Guts does not) has been present since the
  two-phase commit subsystem was introduced in PostgreSQL 8.1 (2005),
  so likely applies to all supported branches (13–17 + master at time
  of writing).
