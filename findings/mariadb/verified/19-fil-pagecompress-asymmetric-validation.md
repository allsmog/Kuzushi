# 19 — `fil_page_decompress_low` is called by two callers with asymmetric size validation

- **Status**: VERIFIED
- **Severity**: medium (the helper trusts `actual_size`; only one of
  the two callers validates it before passing in)
- **File**: `storage/innobase/fil/fil0pagecompress.cc`
- **Line(s)**: 389-465 (`fil_page_decompress_low`); callers at 503-505
  (full_crc32) and 554-555 (non-full_crc32).
- **CWE**: CWE-20 (Improper Input Validation)
- **Discovered by**: `systems-hunt:systems-hunt` (default budget; promoted from queue Q9)
- **Disclosure**: not yet filed

## Summary

`fil_page_decompress_low` takes `actual_size` and forwards it to
zlib/LZ4/LZO/LZMA/BZIP2/Snappy as the input length without any
validation of its own. There are two callers:

- `fil_page_decompress_for_non_full_crc32` (line 520) gates with
  `if (actual_size == 0 || actual_size > srv_page_size - header_len)
  return 0;` (line 550) before calling.
- `fil_page_decompress_for_full_crc32` (line 474) does not validate
  `size - header_len` against either lower or upper bounds before
  the call (line 503-505).

The asymmetry is the source-level confirmation of finding 17 — the
helper was clearly designed to be called only with validated sizes,
but the full-CRC32 caller skipped the validation that the non-full-
CRC32 caller has.

## Source quote

```c
// fil0pagecompress.cc — non-full-CRC32 caller validates:
546:   ulint actual_size = mach_read_from_2(buf + FIL_PAGE_DATA
547:                          + FIL_PAGE_COMP_SIZE);
548:
549:   /* Check if payload size is corrupted */
550:   if (actual_size == 0 || actual_size > srv_page_size - header_len) {
551:     return 0;
552:   }
553:
554:   if (!fil_page_decompress_low(tmp_buf, buf, comp_algo, header_len,
555:                                actual_size)) {

// vs. full-CRC32 caller — no equivalent guard:
493:   if (fil_space_t::full_crc32_page_compressed_len(flags)) {
494:     compile_time_assert(FIL_PAGE_FCRC32_CHECKSUM == 4);
495:     if (size_t lsb = buf[size - 5]) {
496:       size += lsb - 0x100;                  // can underflow
497:     }
498:     size -= 5;                              // can underflow
499:   }
500:
501:   const size_t header_len = FIL_PAGE_COMP_ALGO;
502:
503:   if (!fil_page_decompress_low(tmp_buf, buf,
504:                                fil_space_t::get_compression_algo(flags),
505:                                header_len, size - header_len)) {
```

## Verification notes

- The non-full-CRC32 caller reads `actual_size` as a 16-bit value via
  `mach_read_from_2`, so its upper bound is naturally 65535. Even
  without the guard, the upper bound is `UINT16_MAX`. The guard does
  catch `actual_size == 0` and `actual_size > srv_page_size -
  header_len`, both of which are valid concerns.
- The full-CRC32 caller derives `size` from
  `buf_page_full_crc32_size`, which can return 0 (verified in
  finding 17). After the per-flag length-decode (lines 493-498),
  `size` can be near `SIZE_MAX`. Then `size - header_len` (line 505)
  is also near `SIZE_MAX`.
- The fix proposed in finding 18 (validate inside the helper) closes
  this asymmetry once and for all.

## Suggested fix

See finding 18: validate inside `fil_page_decompress_low`. That makes
the helper safe regardless of caller-side discipline.

## Disclosure plan

Bundle with findings 17/18/20.
