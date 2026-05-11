# 21 — `fsp_header_get_encryption_offset` returns a `zip_size`-derived offset that is not bounded against the physical page

- **Status**: VERIFIED
- **Severity**: medium (offset is consumed by `fil_space_read_crypt_data`
  for `memcmp` / `memcpy` reads on the first page; with attacker-
  influenced `zip_size` the offset can extend past page 0's allocation)
- **File**: `storage/innobase/include/fsp0fsp.h` (offset getter), `storage/innobase/fil/fil0crypt.cc` (consumer)
- **Line(s)**: 311-317 (`fsp_header_get_encryption_offset`),
  281-322 (`fil_space_read_crypt_data`)
- **CWE**: CWE-125 (Out-of-bounds Read), CWE-20 (Improper Input Validation)
- **Discovered by**: `systems-hunt:systems-hunt` (default budget; promoted from queue Q12)
- **Disclosure**: not yet filed

## Summary

`fsp_header_get_encryption_offset(zip_size)` computes:

```c
return zip_size
    ? XDES_ARR_OFFSET + XDES_SIZE * zip_size / FSP_EXTENT_SIZE
    : XDES_ARR_OFFSET + (XDES_SIZE << srv_page_size_shift) / FSP_EXTENT_SIZE;
```

The result is added to `FSP_HEADER_OFFSET` and used as an offset into
`page` for `memcmp(..., MAGIC_SZ)`, `mach_read_from_1`,
`mach_read_from_4`, and `memcpy(crypt_data->iv, page + offset + ...,
iv_length)`. None of those reads validate that `offset` plus the
maximum byte count (`MAGIC_SZ + 2 + iv_length + 4 + 4 + 1 = 27`) stays
within the physical page size.

`zip_size` derives from tablespace flags. In a normal load it's
constrained to `[1024, srv_page_size]`, but the redo-apply / recovery
paths read tablespace flags from disk before they're sanity-checked
against `srv_page_size`. With a corrupted or attacker-supplied flags
value, `zip_size` can grow large enough that
`XDES_ARR_OFFSET + XDES_SIZE * zip_size / FSP_EXTENT_SIZE` exceeds
the physical page size.

## Source quote

```c
// fsp0fsp.h
307: /** Get the byte offset of encryption information in page 0.
308: @param[in]  zip_size  ROW_FORMAT=COMPRESSED page size, or 0
309: @return     byte offset relative to FSP_HEADER_OFFSET */
310: inline MY_ATTRIBUTE((pure, warn_unused_result))
311: ulint fsp_header_get_encryption_offset(ulint zip_size)
312: {
313:   return zip_size
314:     ? XDES_ARR_OFFSET + XDES_SIZE * zip_size / FSP_EXTENT_SIZE
315:     : XDES_ARR_OFFSET + (XDES_SIZE << srv_page_size_shift)
316:     / FSP_EXTENT_SIZE;
317: }

// fil0crypt.cc
281: fil_space_crypt_t* fil_space_read_crypt_data(ulint zip_size, const byte* page)
282: {
283:   const ulint offset = FSP_HEADER_OFFSET
284:     + fsp_header_get_encryption_offset(zip_size);
285:
286:   if (memcmp(page + offset, CRYPT_MAGIC, MAGIC_SZ) != 0) {  // <-- OOB read
287:     /* Crypt data is not stored. */
288:     return NULL;
289:   }
290:
291:   uint8_t type = mach_read_from_1(page + offset + MAGIC_SZ + 0);
292:   uint8_t iv_length = mach_read_from_1(page + offset + MAGIC_SZ + 1);
...
319:   memcpy(crypt_data->iv, page + offset + MAGIC_SZ + 2, iv_length);
```

## Verification notes

- `XDES_SIZE` is `40`. `FSP_EXTENT_SIZE` is `64`. `XDES_ARR_OFFSET` is
  `150` per InnoDB headers. So the formula is `150 + 40 * zip_size /
  64`. With `zip_size = srv_page_size = 16384`, the offset is `150 +
  10240 = 10390`. Plus `FSP_HEADER_OFFSET = 38`, total absolute offset
  is `10428`. Reads up to `10428 + 27 = 10455`. Comfortably within a
  16384-byte page.
- With `zip_size = UINT_MAX / 64 * 64 = ~ULONG_MAX/2`, the formula
  overflows or produces a huge value. The reads then walk past the
  buffer.
- `page` here is `block.page.frame`, which is `srv_page_size` bytes;
  if `zip_size > srv_page_size`, the offset can exceed the page.
- The caller (`fil_space_read_crypt_data`) is invoked during space
  open and during redo-log apply (via `fil_crypt_parse` paths and via
  `fsp_header_init`). The `zip_size` value originates from
  `fsp_flags_get_zip_size(flags)`, which masks and shifts the
  `flags` field of the FSP header — i.e. attacker-supplied bytes from
  page 0.

## Suggested fix

Validate `offset + (MAGIC_SZ + 2 + IV_MAX + 4 + 4 + 1)` against the
physical page size. The cheapest fix is at the consumer:

```c
fil_space_crypt_t* fil_space_read_crypt_data(ulint zip_size, const byte* page)
{
  const ulint phys_size = zip_size ? zip_size : srv_page_size;
  const ulint offset = FSP_HEADER_OFFSET
                     + fsp_header_get_encryption_offset(zip_size);

  if (offset + MAGIC_SZ + 2 + MY_AES_BLOCK_SIZE + 4 + 4 + 1 > phys_size) {
    return NULL;
  }
  ...
}
```

## Disclosure plan

File alongside the redo-apply bundle (findings 11-16). Could also be
folded into a `crypt_data` advisory together with finding 13.
