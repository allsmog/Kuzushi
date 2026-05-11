# 14 — `log_phys_t::undo_append` `free + len + 6` size_t arithmetic can wrap and bypass the bounds check

- **Status**: VERIFIED
- **Severity**: medium (requires `len` near SIZE_MAX from the parse
  path; the recv parse path has weaker length validation than it
  should — see findings 11/12)
- **File**: `storage/innobase/log/log0recv.cc`
- **Line(s)**: 217-246 (`log_phys_t::undo_append`). Wrap at line 231.
- **CWE**: CWE-190 (Integer Overflow / Wraparound), CWE-787 (OOB Write)
- **Discovered by**: `systems-hunt:systems-hunt` (default budget; promoted from queue Q4)
- **Disclosure**: not yet filed

## Summary

`undo_append` validates that the new record fits within the page using:

```c
if (UNIV_UNLIKELY(free < TRX_UNDO_PAGE_HDR + TRX_UNDO_PAGE_HDR_SIZE ||
                  free + len + 6 >= srv_page_size - FIL_PAGE_DATA_END))
```

`free` is `uint16_t` (max 65535), but `len` is `size_t`. The expression
`free + len + 6` is computed in `size_t`. With attacker-controlled
`len ≥ SIZE_MAX - 6`, the addition wraps to a small number that
satisfies `< srv_page_size - FIL_PAGE_DATA_END` (typically 16384 - 8 =
16376), bypassing the upper-bound guard. The subsequent `memcpy(p,
data, len)` at line 242 writes up to ~SIZE_MAX bytes past the
`block.page.frame` buffer.

## Source quote

```c
// log0recv.cc
217:   /** Apply an UNDO_APPEND record.
218:   @see mtr_t::undo_append()
219:   @param block   undo log page
220:   @param data    undo log record
221:   @param len     length of the undo log record
222:   @return whether the operation failed (inconcistency was noticed) */
223:   static bool undo_append(const buf_block_t &block, const byte *data,
224:                           size_t len)
225:   {
226:     ut_ad(len > 2);
227:     byte *free_p= my_assume_aligned<2>
228:       (TRX_UNDO_PAGE_HDR + TRX_UNDO_PAGE_FREE + block.page.frame);
229:     const uint16_t free= mach_read_from_2(free_p);
230:     if (UNIV_UNLIKELY(free < TRX_UNDO_PAGE_HDR + TRX_UNDO_PAGE_HDR_SIZE ||
231:                       free + len + 6 >= srv_page_size - FIL_PAGE_DATA_END))
232:     {
233:       ib::error() << "Not applying UNDO_APPEND due to corruption on "
234:                   << block.page.id();
235:       return true;
236:     }
237:
238:     byte *p= block.page.frame + free;
239:     mach_write_to_2(free_p, free + 4 + len);
240:     memcpy(p, free_p, 2);
241:     p+= 2;
242:     memcpy(p, data, len);              // OOB write when len wraps the guard
243:     p+= len;
244:     mach_write_to_2(p, free);
245:     return false;
246:   }
```

## Verification notes

- `len` is `size_t` (line 224); on 64-bit builds that's 8 bytes.
- The check at line 231 uses native `+` operators; integer-promotion
  rules promote both operands to `size_t`, so the arithmetic is in
  unsigned 64-bit. Wrap is well-defined but defeats the bound.
- Reachability: `len` derives from the parsed record length via the
  recv apply path. Findings 11/12 show that the recv parser lets
  `parse_length` produce values up to `0xFFFFFFFF` and beyond by
  combining `MLOG_DECODE_ERROR` propagation with the `255`-byte
  varint-length error. Whether the caller restricts `len ≤ srv_page_size`
  before passing in is the missing audit step; the code as written
  trusts the caller.
- `mach_write_to_2(free_p, free + 4 + len)` at line 239 also computes
  `free + 4 + len` in `size_t` then truncates to 16 bits — silent
  truncation but defends against data-segment overrun via that store.
  The `memcpy` at 242 is the dangerous primitive.

## Suggested fix

Range-check `len` as a top-level guard before the additive comparison:

```c
if (UNIV_UNLIKELY(len > srv_page_size)) {
  recv_sys.set_corrupt_log();
  return true;
}
if (UNIV_UNLIKELY(free < TRX_UNDO_PAGE_HDR + TRX_UNDO_PAGE_HDR_SIZE ||
                  len + 6 > srv_page_size - FIL_PAGE_DATA_END - free))
{
  ...
}
```

Note the rewrite to subtract on the right-hand side so wrap can't make
the comparison look successful.

## Disclosure plan

Part of the redo-log apply hardening bundle (with findings 11-13).
