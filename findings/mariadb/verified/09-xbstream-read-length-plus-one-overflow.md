# 09 — xbstream_read `chunk->length + 1` integer overflow → heap OOB write

- **Status**: VERIFIED
- **Severity**: high
- **File**: `extra/mariabackup/xbstream_read.cc`
- **Line(s)**: 191-198 (size check), 218-225 (overflow + skipped realloc)
- **CWE**: CWE-190 (Integer Overflow), CWE-787 (OOB Write)
- **Discovered by**: `systems-hunt:systems-hunt` (second batch run; line 218)
- **Disclosure**: not yet filed (recommend extending the existing
  xbstream report at `/home/user/mariadb-disclosures/5-xbstream-write-stack-overflow-and-mismatch.txt`)

## Summary

The size check at line 191 uses `if (ullval > (ulonglong) SIZE_T_MAX)`.
On 64-bit Linux `SIZE_T_MAX == UINT64_MAX`, so this check **never
fires**. `chunk->length` can therefore be set to `SIZE_T_MAX`. Then at
line 218 the realloc-or-not check is `if (chunk->length + 1 >
chunk->buflen)`. `chunk->length + 1` wraps to 0, the condition is
false, and the realloc is **skipped**. The subsequent `F_READ(chunk->data,
chunk->length)` writes up to `SIZE_T_MAX` attacker-controlled bytes
into the **existing** (much smaller) buffer.

## Source quote

```c
// xbstream_read.cc
191: F_READ(tmpbuf, 16);
192: ullval = uint8korr(tmpbuf);
193: if (ullval > (ulonglong) SIZE_T_MAX) {       // dead check on 64-bit
194:   msg("...");
195:   goto err;
196: }
197: chunk->length = (size_t) ullval;
...
218: if (chunk->length + 1 > chunk->buflen) {     // wraps to 0 > buflen → false
219:   chunk->data = my_realloc(...,
220:               chunk->length + 1, ...);        // realloc skipped
...
225:   chunk->buflen = chunk->length + 1;
226: }
... F_READ(chunk->data, chunk->length);            // OOB write
```

## Verification notes

Read in source. `ullval` is `uint64_t` (uint8korr produces a 64-bit
unsigned), `SIZE_T_MAX` on 64-bit Linux equals `UINT64_MAX` (both are
2^64 - 1), so `ullval > SIZE_T_MAX` is always false. Subsequent F_READ
is the OOB write sink.

In practice the OOB write is bounded by what the upstream stream
actually delivers — F_READ may return early on EOF. But ASan would
catch the heap-buffer-overflow on the first byte past `chunk->buflen`.

## Suggested fix

Replace the dead `> SIZE_T_MAX` check with a real bound (e.g.
`if (ullval > xb_stream_max_chunk_length)` where the constant is some
sane page-multiple cap like 256 MB). Also harden the realloc check:
`if (chunk->length >= SIZE_T_MAX || chunk->length + 1 > chunk->buflen)`.

## Disclosure plan

This bug is in the same xbstream module as findings 06 and 07. Three
options:
1. Append a "report 5b" to the existing xbstream disclosure file.
2. File as a separate report.
3. Leave for follow-up.

I'd lean toward option 1 — the maintainers reading the xbstream report
will already be in this code anyway.
