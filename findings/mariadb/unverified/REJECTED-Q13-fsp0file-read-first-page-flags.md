# REJECTED — Q13: `read_first_page_flags` is only invoked on `DB_SUCCESS`, not on partial reads

- **Status**: REJECTED (false positive — control-flow gate prevents the
  hypothesised path)
- **File originally cited**: `storage/innobase/fsp/fsp0file.cc:390`
- **Hypothesis**: A path where `n_read < UNIV_PAGE_SIZE_MIN` still
  calls `read_first_page_flags`, leaving `m_first_page` populated
  with partial data that is then parsed for tablespace flags.
- **Discovered by**: `systems-hunt:systems-hunt` (default budget; queue Q13)

## Why this is rejected

The actual control flow in `Datafile::read_first_page` (lines 280-342)
gates `read_first_page_flags` on `err == DB_SUCCESS`:

```c
// fsp0file.cc
303:   while (page_size >= UNIV_PAGE_SIZE_MIN) {
304:
305:     ulint  n_read = 0;
306:
307:     err = os_file_read(
308:       IORequestReadPartial, m_handle, m_first_page, 0,
309:       page_size, &n_read);
310:
311:     if (err == DB_SUCCESS) {
312:       break;                           // exits with err == DB_SUCCESS
313:     }
314:
315:     if (err == DB_IO_ERROR && n_read == 0) {
316:       break;                           // exits with err == DB_IO_ERROR
317:     }
318:     if (err == DB_IO_ERROR && n_read >= UNIV_PAGE_SIZE_MIN) {
319:       page_size >>= 1;                 // retry with smaller page size
320:     } else if (srv_operation == SRV_OPERATION_BACKUP) {
321:       break;                           // exits with err != DB_SUCCESS
322:     } else {
323:       ib::info() << "Cannot read first page of '"
324:         << m_filepath << "': " << err;
325:       break;                           // exits with err != DB_SUCCESS
326:     }
327:   }
328:
329:   if (err == DB_SUCCESS && m_order == 0) {
330:     err = read_first_page_flags(m_first_page);    // <-- gated
331:   }
```

The only loop exit that reaches line 329 with `err == DB_SUCCESS` is
the `break` at line 312, which is taken when `os_file_read` returned
`DB_SUCCESS` — meaning the full `page_size` bytes were read.

The other two exits (`DB_IO_ERROR && n_read == 0` and the catch-all
`else`) leave `err != DB_SUCCESS`, so line 330 is not executed. The
retry-with-shrunken-page-size branch (line 319) does not exit the
loop; it loops back. `n_read >= UNIV_PAGE_SIZE_MIN` is required to
even take that retry, so even the retry path holds at least
`UNIV_PAGE_SIZE_MIN` bytes.

**Conclusion:** `read_first_page_flags` is only called with a
fully-populated buffer. The agent's claim that "a path where `n_read
< UNIV_PAGE_SIZE_MIN` still calls `read_first_page_flags`" does not
match the source.

## Note for future audits

The retry-page-size loop is the part of this code that an agent might
mis-read. Note that `page_size >>= 1` only fires when the previous
read returned `DB_IO_ERROR` AND `n_read >= UNIV_PAGE_SIZE_MIN` — it's
deliberately reading at *least* `UNIV_PAGE_SIZE_MIN` before deciding
the file is short. If a future patch changes that bound, re-check.
