# 16 — `log_phys_t::append` runs `memcpy` before applying its `uint16_t` length truncation

- **Status**: VERIFIED
- **Severity**: medium (write past record allocation if the upstream
  sized the allocation for the truncated length but the apply path
  passes the un-truncated `size`)
- **File**: `storage/innobase/log/log0recv.cc`
- **Line(s)**: 205-215 (`log_phys_t::append`)
- **CWE**: CWE-190 (Integer Overflow / Wraparound), CWE-787 (Out-of-bounds Write)
- **Discovered by**: `systems-hunt:systems-hunt` (default budget; promoted from queue Q6)
- **Disclosure**: not yet filed

## Summary

`append` writes `size` bytes via `memcpy(end(), recs, size)`, then
recomputes the stored length as `static_cast<uint16_t>(l + size)`.
The truncation happens on the *stored* value, but the `memcpy` already
ran with the actual `size`. If the record was originally allocated
based on an upper-bound predicted by the truncated `len + size` (so
the allocation is sized for `(l + size) % 2^16`), but the actual
`memcpy` writes `size` bytes starting at `end() = begin() + l_old`,
the write runs past the allocation when `l_old + size > UINT16_MAX`.

## Source quote

```c
// log0recv.cc
205:   /** Append a record to the log.
206:   @param recs  log to append
207:   @param size  size of the log, in bytes */
208:   void append(const byte *recs, size_t size)
209:   {
210:     ut_ad(start_lsn < lsn);
211:     uint16_t l= len();
212:     reinterpret_cast<byte*>(memcpy(end(), recs, size))[size]= 0;  // <-- memcpy first
213:     l= static_cast<uint16_t>(l + size);                            // <-- truncate after
214:     memcpy(start(), &l, 2);
215:   }
```

## Verification notes

- `len()` returns `uint16_t` (line 172); `start()`/`end()` are typed
  byte pointers.
- The bug is order-of-operations: the body `memcpy` at line 212 runs
  with the un-truncated `size`. If the record's underlying allocation
  was sized expecting `l + size` to fit in a `uint16_t`, the memcpy
  has already overflowed by the time the truncation at 213 happens.
- The terminating-NUL write `[size] = 0` at line 212 also lands at
  `end() + size`, again with the un-truncated `size`.
- See finding 15 for the constructor-side bug — between the two,
  `log_phys_t` has no consistent `uint16_t` boundary.
- Practical reachability: requires a redo-log apply path that builds
  up a `log_phys_t` from multiple `mtr_t` records and accumulates more
  than 64 KB of payload. The apply path is reachable from any
  recovery / replication scenario. Whether allocator-side guarantees
  prevent the OOB still needs an audit pass — the function as written
  trusts callers and the upstream path to never push past 64 KB.

## Suggested fix

Truncate before the memcpy and refuse oversized appends:

```c
void append(const byte *recs, size_t size)
{
  ut_ad(start_lsn < lsn);
  const uint16_t l_old= len();
  if (UNIV_UNLIKELY(size_t(l_old) + size > UINT16_MAX)) {
    recv_sys.set_corrupt_log();
    return;
  }
  reinterpret_cast<byte*>(memcpy(end(), recs, size))[size]= 0;
  const uint16_t l_new= static_cast<uint16_t>(l_old + size);
  memcpy(start(), &l_new, 2);
}
```

## Disclosure plan

Bundle with redo-log apply hardening (findings 11-15).
