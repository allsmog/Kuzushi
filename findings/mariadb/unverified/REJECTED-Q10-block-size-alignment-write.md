# REJECTED — Q10: `fil_page_compress_for_full_crc32` block-size alignment cannot exceed `out_buf` in current build

- **Status**: REJECTED (false positive; defense-in-depth note retained)
- **File originally cited**: `storage/innobase/fil/fil0pagecompress.cc:520`
- **Hypothesis**: After compression, `write_size` is rounded up to the
  next multiple of `block_size`; when `block_size > srv_page_size -
  actual_size`, the alignment writes past `out_buf`.
- **Discovered by**: `systems-hunt:systems-hunt` (default budget; queue Q10)

## Why this is rejected

The post-compression alignment loop is at lines 220-226:

```c
ut_ad(write_size);
if (write_size & (block_size - 1)) {
  size_t tmp = write_size;
  write_size = (write_size + (block_size - 1))
             & ~(block_size - 1);
  memset(out_buf + tmp, 0, write_size - tmp);
}
```

For the alignment to write past `out_buf`, the aligned `write_size`
must exceed the `out_buf` allocation size. Three constraints prevent
this:

1. **`block_size` is capped at 4096.** `fil_space_get_block_size`
   (`storage/innobase/fil/fil0fil.cc:3253-3273`) explicitly clamps:
   ```c
   if (block_size > 4096) {
     block_size = 512;
   }
   ```
   So `block_size ∈ {512, 1024, 2048, 4096}` (must also be a power
   of 2 by `ut_is_2pow(block_size)` at line 361).

2. **`srv_page_size` is at least `UNIV_PAGE_SIZE_MIN = 4096`.** And
   the comp_buf is `aligned_malloc(srv_page_size, srv_page_size)`
   (`buf0flu.cc:548`) — or larger, if LZO/snappy is loaded.

3. **Pre-alignment `write_size < srv_page_size`** is enforced by
   `if (write_size >= srv_page_size) goto fail;` at line 201.

Because `block_size ≤ srv_page_size` and the input to alignment is `<
srv_page_size`, the aligned value is `≤ srv_page_size`, which fits
exactly in the `out_buf` allocation.

The `row0import.cc:4359` caller hard-codes `block_size = 512`, so the
same reasoning applies a fortiori.

**Conclusion:** No OOB write is reachable via this code path with
the current `block_size` clamp. If a future patch raises the
`fil_space_get_block_size` cap above `srv_page_size`, the bug
becomes real — keeping this finding in the catalog as a
"watch-this-region" note.

## Note for future audits

The `> 4096 ? 512` clamp in `fil_space_get_block_size` is a hard
boundary that effectively prevents the OOB. If the clamp is changed
without updating `fil_page_compress_for_full_crc32`, this will
become a real OOB write into the compression buffer.
