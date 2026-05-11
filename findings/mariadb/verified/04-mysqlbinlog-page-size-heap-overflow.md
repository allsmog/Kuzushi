# 04 — Binlog-in-engine page-size shift heap overflow (`mysqlbinlog`)

- **Status**: VERIFIED
- **Severity**: critical
- **File**: `client/mysqlbinlog-engine.cc`
- **Line(s)**: 744-745 (allocation), 1058 (attacker-controlled assignment), 331-332 (sink)
- **CWE**: CWE-787 (OOB Write), CWE-190 (Integer Overflow), CWE-1335 (Incorrect Bitwise Shift)
- **Discovered by**: `systems-hunt:systems-hunt` (default budget)
- **Disclosure**: filed at `/home/user/mariadb-disclosures/4-binlog-page-size-and-chunk-len.txt`

## Summary

`parse_file_header()` reads a 4-byte little-endian shift exponent
directly from the attacker-controlled binlog file header bytes 4..7 and
assigns `binlog_page_size = 1 << uint4korr(page_buffer + 4)` with no
bounds check. The page buffer was already allocated at a fixed
`BINLOG_PAGE_SIZE_MAX` (65536) via `my_malloc`. Subsequent
`my_pread(fd, buf, binlog_page_size, …)` then reads up to
`(1 << shift)` bytes into that 65536-byte heap allocation. Shift ≥ 17
overflows the heap. Reachable via `mysqlbinlog file.bin` on
attacker-supplied input (forensics, third-party backup ingestion,
hostile replicas).

## Source quote

```c
// mysqlbinlog-engine.cc
62:  static constexpr uint32_t BINLOG_PAGE_SIZE_MAX= 65536;
744:   page_buf= (uchar *)
745:     my_malloc(PSI_NOT_INSTRUMENTED, BINLOG_PAGE_SIZE_MAX, MYF(MY_WME));

// parse_file_header()
1054:    uint32_t vers_major= uint4korr(page_buffer + 8);
1055:    if (vers_major > INNODB_BINLOG_FILE_VERS_MAJOR) ... // only validation
1058:    binlog_page_size= 1 << uint4korr(page_buffer + 4);

// read_page_mysqlbinlog() — sink
331: size_t read= my_pread(fd, buf, binlog_page_size,
332:                       (my_off_t)page_no * binlog_page_size, MYF(0));
```

## Verification notes

Confirmed allocation site, attacker-controlled assignment, and
`my_pread` sink with `binlog_page_size` as length. The only validation
between read and assignment is a `vers_major` version check (line 1054).
Shift of 17 → 131072 bytes; shift ≥ 32 → undefined behaviour on
uint32_t. Secondary OOB read at line 340 (`memcmp(buf, buf+1,
binlog_page_size - 1)`).

## Suggested fix

Range-check the shift before assignment (4096..65536 on the actual
page-size; reject anything outside `[12, 16]` as the shift exponent).
See disclosure doc for diff.
