# 20 — `mtr_t::memset` / `memcpy` / `memmove` bulk page-mutation helpers gate bounds with debug-only asserts

- **Status**: VERIFIED
- **Severity**: low (defense-in-depth — these helpers are the
  last-line-of-defense bounds check; if any caller computes a bad
  offset/length, release builds have no guard)
- **File**: `storage/innobase/include/mtr0log.h`
- **Line(s)**: 168-174 (`memset` single-byte), 207-221 (`memset`
  repeating string — separately covered by finding 10 stride bug),
  228-234 (`memcpy`), 269-299 (`memmove`).
- **CWE**: CWE-617 (Reachable Assertion → silent in release), CWE-787
  (OOB Write surface)
- **Discovered by**: `systems-hunt:systems-hunt` (default budget; promoted from queue Q11)
- **Disclosure**: not yet filed

## Summary

Every public `mtr_t` page-mutation helper guards offset/length bounds
with `ut_ad`, which is compiled out in release builds:

- `memset(buf_block_t*, ulint, ulint, byte)` (line 168) —
  `ut_ad(ofs <= srv_page_size); ut_ad(ofs + len <= srv_page_size);`
- `memset(buf_block_t*, ulint, size_t, const void*, size_t)` (line 207)
  — same pair plus `ut_ad(len > size)`. (See finding 10 for a
  separate stride-counter bug in this overload.)
- `memcpy(buf_block_t&, ulint, ulint)` (line 228) —
  `ut_ad(offset <= srv_page_size); ut_ad(offset + len <= srv_page_size);`
- `memmove(buf_block_t&, ulint, ulint, ulint)` (line 269) —
  five `ut_ad`s on `s`, `d`, `len` and their sums.

In release builds none of these gates run. If any caller computes a
bad offset/length (overflow, wrap, sign-flip), the helper writes past
the page frame.

## Source quote

```c
// mtr0log.h
168: inline void mtr_t::memset(const buf_block_t *b, ulint ofs, ulint len, byte val)
169: {
170:   ut_ad(ofs <= ulint(srv_page_size));            // <-- debug only
171:   ut_ad(ofs + len <= ulint(srv_page_size));      // <-- debug only
172:   ::memset(ofs + b->page.frame, val, len);
173:   memset(*b, ofs, len, val);
174: }

228: inline void mtr_t::memcpy(const buf_block_t &b, ulint offset, ulint len)
229: {
230:   ut_ad(len);                                    // <-- debug only
231:   ut_ad(offset <= ulint(srv_page_size));         // <-- debug only
232:   ut_ad(offset + len <= ulint(srv_page_size));   // <-- debug only
233:   memcpy_low(b, uint16_t(offset), &b.page.frame[offset], len);
234: }

269: inline void mtr_t::memmove(const buf_block_t &b, ulint d, ulint s, ulint len)
270: {
271:   ut_ad(d >= 8);
272:   ut_ad(s >= 8);
273:   ut_ad(len);
274:   ut_ad(s <= ulint(srv_page_size));
275:   ut_ad(s + len <= ulint(srv_page_size));
276:   ut_ad(s != d);
277:   ut_ad(d <= ulint(srv_page_size));
278:   ut_ad(d + len <= ulint(srv_page_size));
279:   ...
```

## Verification notes

- `b->page.frame` is a `srv_page_size`-sized buffer-pool buffer.
  Writes past `srv_page_size` from this base hit adjacent buffer-pool
  state (other pages, allocator metadata, etc.).
- `memcpy_low` (the underlying logger) cast `offset` to `uint16_t` at
  line 233 — that truncates silently when `offset > 65535`, but
  `srv_page_size <= 65536` so the truncation matches the page bound.
  The actual `::memcpy` further down (line 252) uses the un-truncated
  `len`, so a wrap/overflow in the caller still results in a real
  OOB write.
- This finding is independent of finding 10 (the stride-counter bug
  in the repeating-string overload) — finding 10 is a logic bug that
  fires even with valid inputs; this finding (Q11) is the
  defence-in-depth gap that makes any other caller-side bug exploitable.
- Reachability requires identifying a caller that passes attacker-
  influenced offset/length. Promising starting points: redo-log
  apply (which is fed parsed-record data — see findings 11/12/14),
  any code path that derives offsets from page-internal counters
  that wrap (the kind of place finding 16 lives in).

## Suggested fix

Convert each `ut_ad` pair to `if (UNIV_UNLIKELY(...)) ut_error_str(...);`
or similar, so release builds have a runtime guard. Example:

```c
inline void mtr_t::memset(const buf_block_t *b, ulint ofs, ulint len, byte val)
{
  if (UNIV_UNLIKELY(ofs > ulint(srv_page_size)) ||
      UNIV_UNLIKELY(ofs + len > ulint(srv_page_size)) ||
      UNIV_UNLIKELY(ofs + len < ofs))             // wrap
  {
    ut_error_string("mtr_t::memset out-of-bounds");
  }
  ::memset(ofs + b->page.frame, val, len);
  memset(*b, ofs, len, val);
}
```

## Disclosure plan

Defense-in-depth note. Worth raising with the InnoDB team but not a
disclosure on its own. Reference from the apply-path bundle (findings
11-16) since some of those bugs would be caught here if release
guards existed.
