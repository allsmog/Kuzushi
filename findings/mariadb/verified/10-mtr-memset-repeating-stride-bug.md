# 10 — `mtr_t::memset` repeating-string loop increments by `len` instead of `size`

- **Status**: VERIFIED
- **Severity**: medium (in-memory stale-byte exposure + on-disk dirty
  flush before crash recovery normalises). Probably not memory-safety,
  but a clear correctness/integrity bug.
- **File**: `storage/innobase/include/mtr0log.h`
- **Line(s)**: 207-221 (`mtr_t::memset(buf_block_t*, ulint, size_t, const void*, size_t)` overload). Bug at line 217.
- **CWE**: CWE-682 (Incorrect Calculation), CWE-908 (Use of Uninitialized
  Resource — for the in-memory window), CWE-200 (info exposure if
  flushed before recovery)
- **Discovered by**: `systems-hunt:systems-hunt` (default budget; promoted from UNVERIFIED queue item 23)
- **Disclosure**: not yet filed

## Summary

The repeating-string memset overload tiles `str` (length `size`) across
`len` bytes of a buffer page. The loop body runs once, then the
increment is wrong:

```c
size_t s = 0;
while (s < len) {
  ::memcpy(ofs + s + b->page.frame, str, size);
  s += len;        // BUG: should be s += size
}
::memcpy(ofs + s + b->page.frame, str, len - s); // copies 0 bytes
```

Net effect: only the first `size` bytes of the target region are
filled. The remaining `len - size` bytes retain whatever was at that
buffer-pool position previously. Meanwhile the companion logger (sister
overload at line 182) emits a redo-log MEMSET record advertising `len`
bytes were filled (`mlog_encode_varint(l, len)` at line 194), and
`set_modified(b)` marks the page dirty.

## Source quote

```c
// mtr0log.h
207: inline void mtr_t::memset(const buf_block_t *b, ulint ofs, size_t len,
208:                           const void *str, size_t size)
209: {
210:   ut_ad(ofs <= ulint(srv_page_size));
211:   ut_ad(ofs + len <= ulint(srv_page_size));
212:   ut_ad(len > size); /* use mtr_t::memcpy() for shorter writes */
213:   size_t s= 0;
214:   while (s < len)
215:   {
216:     ::memcpy(ofs + s + b->page.frame, str, size);
217:     s+= len;                                  // <-- s += size
218:   }
219:   ::memcpy(ofs + s + b->page.frame, str, len - s);
220:   memset(*b, ofs, len, str, size);
221: }
```

## Verification notes

Read end-to-end. The `mtr_t::memset(*b, ofs, len, str, size)` call at
line 220 forwards to the sister overload starting at 182, which does
the redo-log encoding (line 194: `mlog_encode_varint(l, len);`). So the
redo log claim is `len`; the in-memory write is `size`.

Practical impact analysis:

1. **Crash recovery is correct.** On replay, the redo-log apply path
   reads the MEMSET record with length `len` and tiles `str` correctly.
   So a clean recovered server is consistent.

2. **In-memory before flush.** Other transactions reading the page can
   see the stale `len - size` bytes between the bug firing and either
   crash + recovery or a redo-log apply that overwrites the same range.
   That's a window for stale-buffer-pool-content exposure.

3. **On-disk before crash.** If the dirty page is flushed before crash
   (normal background flushing), the on-disk page now has stale bytes
   in the `[ofs+size, ofs+len)` range. A clean restart (no recovery)
   uses the on-disk page as-is. Operator workflow that relies on
   "we wrote the file out cleanly" sees corrupt data; recovery from
   that point would need an undo/log replay that may no longer be
   available depending on retention.

4. **Where it fires.** Need to enumerate callers — `len > size` is the
   precondition (line 212 ut_ad). If the only callers in practice use
   `len == size + small_constant` and the page is reliably re-flushed
   after recovery, impact is theoretical. If there are larger-scale
   tilers, impact is real.

## Suggested fix

One-character: `s += len;` → `s += size;`. Also, given the trailing
memcpy currently always copies 0 bytes (because the loop exits with
`s == len`), the trailing memcpy probably wants to be inside the loop
body or removed:

```c
size_t s = 0;
while (s + size <= len) {
  ::memcpy(ofs + s + b->page.frame, str, size);
  s += size;
}
if (s < len) {
  ::memcpy(ofs + s + b->page.frame, str, len - s);
}
```

## Disclosure plan

This is in InnoDB core. File as a MariaDB security report with the
clear caveat that crash recovery normalises the state — the impact is
on the in-memory window and any flush that happens before recovery.
Not the highest-severity item to report, but a clean bug worth fixing.
