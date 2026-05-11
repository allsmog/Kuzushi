# 07 — xbstream writer/reader off-by-one (`> FN_REFLEN` vs `>= FN_REFLEN`)

- **Status**: VERIFIED (real bug; severity overstated as "medium" by the model — closer to low/parser robustness)
- **Severity**: low
- **File**: `extra/mariabackup/xbstream_write.cc:96` ↔ `extra/mariabackup/xbstream_read.cc:148`
- **CWE**: CWE-193 (Off-by-one), CWE-1023
- **Discovered by**: `systems-hunt:systems-hunt`
- **Disclosure**: filed alongside finding 06 at `/home/user/mariadb-disclosures/5-xbstream-write-stack-overflow-and-mismatch.txt`

## Summary

Writer's `xb_stream_write_open` allows `path_len == FN_REFLEN` (rejects
`> FN_REFLEN`), but the reader's `xb_stream_read_chunk` at line 148
rejects `pathlen >= FN_REFLEN` — so a writer-emitted archive with a
path of exactly `FN_REFLEN` bytes is unparseable by the same version's
reader. Round-trip break, not memory safety. Same shape at
`xbstream_read.cc:173` for the rename chunk's `new_pathlen`.

## Source quote

```c
// writer (accepts ==FN_REFLEN)
xbstream_write.cc:96: if (path_len > FN_REFLEN) {
xbstream_write.cc:97:   msg("xb_stream_write_open(): file path is too long.");
xbstream_write.cc:98:   return NULL;
xbstream_write.cc:99: }

// reader (rejects ==FN_REFLEN)
xbstream_read.cc:148: if (pathlen >= FN_REFLEN) {
xbstream_read.cc:149:   msg("xb_stream_read_chunk(): path length (%lu) is too large at "
xbstream_read.cc:150:       "offset 0x%llx.", (ulong) pathlen, stream->offset);
xbstream_read.cc:151:   goto err;
```

## Verification notes

Read both files. `chunk->path` is declared `char path[FN_REFLEN]`
(xbstream.h:95). Reader's check at 148 + the NUL-write at line 163
(`chunk->path[pathlen] = '\0';`) means values 0..FN_REFLEN-1 are
accepted and write the NUL at the last array byte — in bounds. So the
mismatch is purely a round-trip issue: writer emits, reader rejects.
Operational symptom is "path length too large" parse errors mid-restore.

NOTE: the model originally marked this as a stack-overflow risk. I
checked and the array is exactly `FN_REFLEN` bytes — the NUL writes
in-bounds.

## Suggested fix

Pick one bound (`> FN_REFLEN` vs `>= FN_REFLEN`) and apply it to all
four sites: write_open / write_remove / write_rename / read_chunk +
read_chunk's rename branch. Add a regression test for path length
exactly FN_REFLEN.
