# 05 — Binlog 16-bit `chunk_len` parsed without per-page bounds check

- **Status**: VERIFIED (real bug; severity overstated as "high" by the model — closer to medium info-leak when standalone)
- **Severity**: medium standalone (info leak within the heap allocation); high when combined with finding 04
- **File**: `client/mysqlbinlog-engine.cc`
- **Line(s)**: 445-486 (three identical parse sites); 504-505 (sink)
- **CWE**: CWE-125 (Out-of-bounds Read), CWE-119
- **Discovered by**: `systems-hunt:systems-hunt`
- **Disclosure**: filed alongside finding 04 at `/home/user/mariadb-disclosures/4-binlog-page-size-and-chunk-len.txt`

## Summary

Three sites parse `chunk_len` as a 16-bit big-endian value
(`page_buffer[off+1] | (page_buffer[off+2] << 8)`), max 0xFFFF. The
sink at line 504-505 does
`memcpy(buffer, page_buffer + s.in_page_offset + 3 + s.chunk_read_offset, size)`
where `size = min(max_len, chunk_len - chunk_read_offset)`. There is no
check that `in_page_offset + 3 + chunk_len <= binlog_page_size`. The
existing page-transition check at line 421 only guarantees
`in_page_offset < binlog_page_size - (BINLOG_PAGE_DATA_END + 3)` — it
doesn't bound the end of the chunk read against `binlog_page_size`.

## Source quote

```c
445: s.chunk_len= page_buffer[s.in_page_offset + 1] |
446:   ((uint32_t)page_buffer[s.in_page_offset + 2] << 8);
504: size= std::min((uint32_t)max_len, s.chunk_len - s.chunk_read_offset);
505: memcpy(buffer, page_buffer + s.in_page_offset + 3 + s.chunk_read_offset, size);
```

## Verification notes

Standalone, the OOB read is **bounded by the 65536-byte heap
allocation** (page_buf is sized to `BINLOG_PAGE_SIZE_MAX`), so it leaks
adjacent stale page bytes within the same allocation rather than
out-of-allocation memory. Combined with finding 04 (where
`binlog_page_size` is already > 65536), the read goes outside the
allocation entirely. Treated this as info-leak severity in the
disclosure; combine with finding 04 for full impact.

## Suggested fix

Range-check `chunk_len` against remaining page bytes at all three parse
sites before the memcpy. See disclosure doc.
