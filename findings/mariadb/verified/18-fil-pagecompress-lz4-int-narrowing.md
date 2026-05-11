# 18 — `fil_page_decompress_low` narrows `size_t actual_size` to `int` before passing to `LZ4_decompress_safe`

- **Status**: VERIFIED
- **Severity**: medium (large/wrap values become negative `int`s; LZ4
  treats negative inputs in implementation-defined ways and may read
  past the buffer)
- **File**: `storage/innobase/fil/fil0pagecompress.cc`
- **Line(s)**: 410-416 (LZ4 branch in `fil_page_decompress_low`)
- **CWE**: CWE-197 (Numeric Truncation), CWE-704 (Incorrect Type
  Conversion), CWE-125 (Out-of-bounds Read).
- **Discovered by**: `systems-hunt:systems-hunt` (default budget; promoted from queue Q8)
- **Disclosure**: not yet filed

## Summary

`fil_page_decompress_low` accepts `actual_size` as `ulint` (unsigned,
machine-word) and casts it to `int` before passing to
`LZ4_decompress_safe`. With attacker-controlled `actual_size` larger
than `INT_MAX`, the cast is implementation-defined (`(int) huge`
typically becomes a negative two's-complement value). LZ4's
`LZ4_decompress_safe` interprets a negative `compressedSize` as
"return -1" in some versions, but historic LZ4 paths treated it as
an unsigned size cast back inside the function — which would still
read past the input buffer.

When this is reached via finding 17 (`actual_size` near `SIZE_MAX`
after underflow), the practical effect is "LZ4 reads attacker-
controlled large buffer of memory immediately following `buf +
header_len`".

## Source quote

```c
// fil0pagecompress.cc
389: static bool fil_page_decompress_low(
390:   byte*    tmp_buf,
391:   byte*    buf,
392:   ulint    comp_algo,
393:   ulint    header_len,
394:   ulint    actual_size)        // <-- size_t / ulint
395: {
396:   switch (comp_algo) {
...
410:   case PAGE_LZ4_ALGORITHM:
411:     return LZ4_decompress_safe(
412:       reinterpret_cast<const char*>(buf) + header_len,
413:       reinterpret_cast<char*>(tmp_buf),
414:       static_cast<int>(actual_size),                     // <-- narrowing
415:       static_cast<int>(srv_page_size)) ==
416:       static_cast<int>(srv_page_size);
```

## Verification notes

- `actual_size` reaches this function from two places:
  1. `fil_page_decompress_for_full_crc32` (full CRC32 path) — see
     finding 17, where `size` can underflow to ~`SIZE_MAX`.
  2. `fil_page_decompress_for_non_full_crc32` (non-full CRC32 path) —
     gated by `actual_size > srv_page_size - header_len` (line 550),
     which prevents the LZ4 narrowing here. So this surface is
     entirely fed by the full CRC32 underflow.
- `srv_page_size` is bounded to `[UNIV_PAGE_SIZE_MIN,
  UNIV_PAGE_SIZE_MAX]` (4 KB to 64 KB), so the destination cast at
  line 415 is safe.
- The casted `actual_size` is *also* used for the BZIP2 branch
  (`uint dst_pos = uint(srv_page_size)`, line 442; `uint(actual_size)`,
  line 447) — same narrowing concern, but BZ2 uses `unsigned`, not
  `int`, so it doesn't go negative; it just truncates to the low 32
  bits.

## Suggested fix

Reject `actual_size > srv_page_size - header_len` at the top of
`fil_page_decompress_low`, mirroring the non-full-CRC32 caller:

```c
static bool fil_page_decompress_low(byte *tmp_buf, byte *buf,
                                    ulint comp_algo, ulint header_len,
                                    ulint actual_size)
{
  if (UNIV_UNLIKELY(actual_size == 0 ||
                    actual_size > srv_page_size - header_len)) {
    return false;
  }
  switch (comp_algo) { ... }
}
```

This both fixes the `int` narrowing here and prevents the LZ4/zlib/LZO
APIs from being called with attacker-controlled large inputs in the
full-CRC32 path.

## Disclosure plan

Bundle with findings 17/19/20.
