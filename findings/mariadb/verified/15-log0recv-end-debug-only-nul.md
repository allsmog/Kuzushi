# 15 — `log_phys_t::end()` debug-only NUL-terminator assert

- **Status**: VERIFIED
- **Severity**: low (defensive — release builds have no runtime guard
  that the sentinel byte is NUL; if a caller relies on it for stop
  detection, they walk past the record)
- **File**: `storage/innobase/log/log0recv.cc`
- **Line(s)**: 177 (`log_phys_t::end`)
- **CWE**: CWE-617 (Reachable Assertion → silent in release), CWE-126
  (Buffer Over-read) for callers that walk past `end()` looking for
  NUL.
- **Discovered by**: `systems-hunt:systems-hunt` (default budget; promoted from queue Q5)
- **Disclosure**: not yet filed

## Summary

`log_phys_t` is a redo-log record container. Its constructor at line
202 writes a sentinel `0` byte at `begin()[size]`, and `end()` is
defined as `begin() + len()` with the assertion `ut_ad(!*e)` — the
caller is expected to find a NUL byte at `*end()`. In release builds
the assertion is compiled out; if the construction is corrupted (e.g.
through finding 16's `uint16_t` length truncation, or through any
other bug that lets `len` grow without re-writing the trailing zero)
the byte at `end()` is whatever was there. Callers that scan
`begin()..` looking for NUL as a record terminator will run past the
allocation.

## Source quote

```c
// log0recv.cc
174:   /** @return start of the log records */
175:   byte *begin() { return start() + 2; }
176:   /** @return end of the log records */
177:   byte *end() { byte *e= begin() + len(); ut_ad(!*e); return e; }
178: public:
...
194:   log_phys_t(lsn_t start_lsn, lsn_t lsn, const byte *recs, size_t size) :
195:     log_rec_t(lsn), start_lsn(start_lsn)
196:   {
197:     ut_ad(start_lsn);
198:     ut_ad(start_lsn < lsn);
199:     const uint16_t len= static_cast<uint16_t>(size);
200:     ut_ad(len == size);                                  // <-- debug only
201:     memcpy(start(), &len, 2);
202:     reinterpret_cast<byte*>(memcpy(begin(), recs, size))[size]= 0;
203:   }
```

## Verification notes

- `len` field is stored at `start()` via `memcpy(start(), &len, 2)` so
  it's a `uint16_t`. The constructor truncates `size` to 16 bits then
  asserts equality only via `ut_ad`. So with `size > UINT16_MAX`, the
  stored `len` is the low 16 bits, but `[size] = 0` writes the NUL at
  the *true* size.
- See finding 16 for the `append`-side companion bug where the
  `uint16_t` truncation happens after `memcpy` has already run.
- `end()` is `const`-overloaded (line 182) and called by the apply-
  loop dispatch.
- This is "defensive" in that there's no direct OOB-write primitive
  here — but the record-walk apply loops in the same file rely on
  finding the trailing NUL to detect end-of-record. With the NUL
  missing, a sufficiently corrupted record can extend the apply
  walker into adjacent allocator metadata.

## Suggested fix

Promote the assertion to a runtime check that fails the redo-log
apply, and guard `end()` similarly:

```c
log_phys_t(lsn_t start_lsn, lsn_t lsn, const byte *recs, size_t size) ...
{
  if (UNIV_UNLIKELY(size > UINT16_MAX)) {
    /* abandon — record too large to encode */
    recv_sys.set_corrupt_log();
    return;
  }
  ...
}
```

## Disclosure plan

Part of the redo-log apply hardening bundle (findings 11-14, 16).
