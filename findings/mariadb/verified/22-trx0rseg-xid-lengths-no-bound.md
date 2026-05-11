# 22 — `trx_rseg_read_wsrep_checkpoint` reads `gtrid_length` and `bqual_length` from on-disk page without bounding

- **Status**: VERIFIED (reduced severity)
- **Severity**: low (defense-in-depth — `wsrep_is_wsrep_xid` filters
  out ill-shaped XIDs at line 204, and the on-disk consumers
  (`innodb_binlog.cc:598-602`) use `ut_a` release-active asserts)
- **File**: `storage/innobase/trx/trx0rseg.cc`
- **Line(s)**: 182-205 (`trx_rseg_read_wsrep_checkpoint`)
- **CWE**: CWE-20 (Improper Input Validation)
- **Discovered by**: `systems-hunt:systems-hunt` (default budget; promoted from queue Q14)
- **Disclosure**: not yet filed (likely no advisory; defensive note)

## Summary

`trx_rseg_read_wsrep_checkpoint` reads `xid.gtrid_length` and
`xid.bqual_length` from the rseg header page via `mach_read_from_4`
(line 193-199) and casts them to `int`. The function does not bound
these values against `XIDDATASIZE` (128) or `MAXGTRIDSIZE` (64)
before assigning. Downstream code (`trx0undo.cc:593-596`,
`trx0rseg.cc:67-69`) only validates with `DBUG_ASSERT` (debug-only).

The practical impact is mitigated by:

1. `wsrep_is_wsrep_xid` (sql/wsrep_xid.cc:67-79), invoked at line 204,
   requires `gtrid_length == WSREP_XID_GTRID_LEN_V_1_2` or
   `WSREP_XID_GTRID_LEN_V_3` — fixed values. Out-of-range XIDs are
   rejected at the rseg-read boundary.
2. The other downstream consumer, `innodb_binlog.cc:598-602`, has
   `ut_a(xid->gtrid_length >= 0 && xid->gtrid_length <= 64)` which is
   release-active.

So the missing bound at `trx0rseg.cc:193-199` does not produce a
direct OOB read/write — but it is still a defense-in-depth gap, and
if a future patch reuses `trx_rseg_read_wsrep_checkpoint` outside the
`wsrep_is_wsrep_xid` gate (or relaxes that gate), the bug becomes
real.

## Source quote

```c
// trx0rseg.cc
182: static
183: bool trx_rseg_read_wsrep_checkpoint(const buf_block_t *rseg_header, XID &xid)
184: {
185:   int formatID = static_cast<int>(
186:     mach_read_from_4(TRX_RSEG + TRX_RSEG_WSREP_XID_FORMAT
187:          + rseg_header->page.frame));
188:   if (formatID == 0) {
189:     return false;
190:   }
191:
192:   xid.formatID = formatID;
193:   xid.gtrid_length = static_cast<int>(
194:     mach_read_from_4(TRX_RSEG + TRX_RSEG_WSREP_XID_GTRID_LEN
195:          + rseg_header->page.frame));        // <-- no bound check
196:
197:   xid.bqual_length = static_cast<int>(
198:     mach_read_from_4(TRX_RSEG + TRX_RSEG_WSREP_XID_BQUAL_LEN
199:          + rseg_header->page.frame));        // <-- no bound check
200:
201:   memcpy(xid.data, TRX_RSEG + TRX_RSEG_WSREP_XID_DATA
202:          + rseg_header->page.frame, XIDDATASIZE);
203:
204:   return wsrep_is_wsrep_xid(&xid);
205: }
```

## Verification notes

- `XIDDATASIZE` is `128`; `MAXGTRIDSIZE` is `64`; `MAXBQUALSIZE` is
  `64`. The XID format defines these as the protocol limits; the
  on-disk format inherits them.
- `wsrep_is_wsrep_xid` (sql/wsrep_xid.cc:70-78) checks
  `xid->gtrid_length == WSREP_XID_GTRID_LEN_V_1_2` or
  `WSREP_XID_GTRID_LEN_V_3`. So in the WSREP path, a malformed length
  is filtered.
- The non-WSREP callers of similar code (`trx0undo.cc:629-632`) read
  the same fields and may not have the same gate. Reviewing those is
  a follow-up.
- `trx0trx.cc:376-377` uses `xid.gtrid_length + xid.bqual_length` as
  an offset into `xid.data` for `MEM_MAKE_DEFINED`, which is a
  Valgrind/MSAN annotation — only impactful in instrumented builds.

## Suggested fix

Bound the values at the read site as a defense-in-depth measure:

```c
xid.gtrid_length = static_cast<int>(
    mach_read_from_4(TRX_RSEG + TRX_RSEG_WSREP_XID_GTRID_LEN
         + rseg_header->page.frame));
xid.bqual_length = static_cast<int>(
    mach_read_from_4(TRX_RSEG + TRX_RSEG_WSREP_XID_BQUAL_LEN
         + rseg_header->page.frame));

if (xid.gtrid_length < 0 || xid.bqual_length < 0 ||
    xid.gtrid_length > MAXGTRIDSIZE ||
    xid.bqual_length > MAXBQUALSIZE ||
    xid.gtrid_length + xid.bqual_length > XIDDATASIZE) {
  return false;
}
```

## Disclosure plan

Defense-in-depth note. Don't file as a standalone advisory; track in
the catalog and raise next time the rseg-XID code is touched. If the
non-WSREP siblings (`trx0undo.cc:629-632` etc.) turn out to have
attacker-reachable consumers without the `wsrep_is_wsrep_xid` gate,
revisit severity.
