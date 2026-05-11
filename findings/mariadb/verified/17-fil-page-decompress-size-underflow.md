# 17 — `fil_page_decompress_for_full_crc32` underflows `size` and OOB-reads `buf[size - 5]`

- **Status**: VERIFIED
- **Severity**: high (size_t underflow → up to ~SIZE_MAX bytes handed
  to zlib/LZ4/LZO/LZMA as input length; reachable via crafted
  compressed page in the buffer pool)
- **File**: `storage/innobase/fil/fil0pagecompress.cc`
- **Line(s)**: 474-512 (`fil_page_decompress_for_full_crc32`). Bug at lines 489-505.
- **CWE**: CWE-191 (Integer Underflow), CWE-125 (Out-of-bounds Read).
- **Discovered by**: `systems-hunt:systems-hunt` (default budget; promoted from queue Q7)
- **Disclosure**: not yet filed

## Summary

For a page with the FCRC32 page-compress marker, `size` is computed by
`buf_page_full_crc32_size`, which can return values down to `0` (when
the high byte of the page type, after stripping the marker bit and
shifting left 8, equals 0 — see `buf0buf.h:343`).

The current code only filters `size >= srv_page_size`. With `size = 0`
(or `1..4`), three things happen, in order:

1. `buf[size - 5]` is an OOB read of up to 5 bytes pre-buffer (line 495).
2. If the returned LSB is non-zero, `size += lsb - 0x100` underflows
   `size_t` to a value near `SIZE_MAX`.
3. `size -= 5` keeps it near `SIZE_MAX`.
4. `fil_page_decompress_low(..., size - header_len)` is called with
   that near-`SIZE_MAX` length, which gets cast to `int` for LZ4 (see
   finding 18) and forwarded to zlib/LZO/LZMA otherwise. All the
   decompressors then read from / write to `buf` and `tmp_buf` based
   on attacker-controlled lengths.

## Source quote

```c
// fil0pagecompress.cc
474: static size_t fil_page_decompress_for_full_crc32(byte *tmp_buf, byte *buf,
475:                                                  uint32_t flags)
476: {
477:   ut_ad(fil_space_t::full_crc32(flags));
478:   bool compressed = false;
479:   size_t size = buf_page_full_crc32_size(buf, &compressed, NULL);
480:   if (!compressed) {
481:     ut_ad(size == srv_page_size);
482:     return size;
483:   }
484:
485:   if (!fil_space_t::is_compressed(flags)) {
486:     return 0;
487:   }
488:
489:   if (size >= srv_page_size) {
490:     return 0;                              // upper-bound-only guard
491:   }
492:
493:   if (fil_space_t::full_crc32_page_compressed_len(flags)) {
494:     compile_time_assert(FIL_PAGE_FCRC32_CHECKSUM == 4);
495:     if (size_t lsb = buf[size - 5]) {       // OOB read when size < 5
496:       size += lsb - 0x100;                  // size_t underflow when lsb < 0x100
497:     }
498:     size -= 5;                              // further underflow when size < 5
499:   }
500:
501:   const size_t header_len = FIL_PAGE_COMP_ALGO;
502:
503:   if (!fil_page_decompress_low(tmp_buf, buf,
504:                                fil_space_t::get_compression_algo(flags),
505:                                header_len, size - header_len)) {
506:     return 0;
507:   }
```

## Verification notes

`buf_page_full_crc32_size` proves `size = 0` is reachable. Quoting
`buf0buf.h`:

```c
// buf0buf.h
333:   uint t = fil_page_get_type(buf);
334:   uint page_size = uint(srv_page_size);
335:
336:   if (!(t & 1U << FIL_PAGE_COMPRESS_FCRC32_MARKER)) {
337:     return page_size;
338:   }
339:
340:   t &= ~(1U << FIL_PAGE_COMPRESS_FCRC32_MARKER);
341:   t <<= 8;
342:
343:   if (t < page_size) {
344:     page_size = t;          // <-- can be 0
345:     ...
346:   }
```

Concretely, with the page-type bytes `0x80 0x00`:
- `fil_page_get_type` reads them as `0x8000`.
- The high bit (`FIL_PAGE_COMPRESS_FCRC32_MARKER`) is set, so we
  enter the marker branch.
- After clearing the marker bit, `t = 0`.
- After `t <<= 8`, `t = 0`.
- `0 < page_size` (true for any nonzero page size), so `page_size =
  0`, `*comp = true`.
- Return `0`.

Back in the caller: `size == 0`. The `size >= srv_page_size` guard
fails (`0 < srv_page_size`). Inside the `if
(full_crc32_page_compressed_len(flags))` branch, `buf[size - 5] = buf[-5]`
— OOB read 5 bytes pre-buffer. Whatever is there becomes `lsb`. Then
`size += lsb - 0x100`. If `lsb == 0`, the inner `if` is skipped, but
the unconditional `size -= 5` underflows to ~`SIZE_MAX`. If `lsb !=
0`, `size += lsb - 0x100` underflows the same way.

The result feeds the decompressor (zlib / LZ4 / LZO / LZMA) as the
input length.

## Suggested fix

Add a positive-lower-bound guard before the underflow site:

```c
if (size < FIL_PAGE_COMP_ALGO + 5) {  // need at least header + checksum
  return 0;
}
```

Or, more explicitly, validate `size` is in `[FIL_PAGE_COMP_ALGO + 5,
srv_page_size)` before any of the size arithmetic.

## Disclosure plan

Bundle with findings 18-20 (the rest of the page-decompress family)
as a single "page_compressed format hardening" advisory.
