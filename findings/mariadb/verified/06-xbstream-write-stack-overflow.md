# 06 — `xb_stream_write_remove` / `_rename` lack runtime path-len check

- **Status**: VERIFIED
- **Severity**: high
- **File**: `extra/mariabackup/xbstream_write.cc`
- **Line(s)**: 333-360 (`xb_stream_write_remove`); 365-… (`xb_stream_write_rename`)
- **CWE**: CWE-121 (Stack-based Buffer Overflow), CWE-787, CWE-120
- **Discovered by**: `systems-hunt:systems-hunt`
- **Disclosure**: filed at `/home/user/mariadb-disclosures/5-xbstream-write-stack-overflow-and-mismatch.txt`

## Summary

Both functions declare a fixed stack buffer
`uchar tmpbuf[… + FN_REFLEN]`, then `strlen()` the caller-supplied path
and `memcpy` it into the buffer with no runtime length check — only an
`xb_ad(ptr <= tmpbuf + sizeof(tmpbuf))` debug assertion that's compiled
out in release builds. The sister function `xb_stream_write_open()` at
line 96 in the same file *does* have the check (`if (path_len >
FN_REFLEN)`). Path > FN_REFLEN ⇒ stack buffer overflow with
attacker-controlled bytes (the path itself).

## Source quote

```c
// xbstream_write.cc, write_remove
335: uchar tmpbuf[sizeof(XB_STREAM_CHUNK_MAGIC) - 1 + 1 + 1 + 4 + FN_REFLEN];
344: size_t path_len = strlen(path);   // no length validation
348: memcpy(ptr, path, path_len);
351: xb_ad(ptr <= tmpbuf + sizeof(tmpbuf));   // debug-only

// write_open (reference: has the runtime check)
94:  path_len = strlen(path);
96:  if (path_len > FN_REFLEN) {
97:    msg("xb_stream_write_open(): file path is too long.");
98:    return NULL;
99:  }
```

## Verification notes

`xb_ad` is the mariabackup project's debug-only assert macro; release
builds compile it out, leaving zero runtime guard. Delivery: any path
flowing into either function from a backup-tree iteration where
filenames are attacker-influenced (xbstream archive replay,
shared-staging dirs, etc.).

## Suggested fix

Add the same `if (path_len > FN_REFLEN) return 1;` check to both
functions. While touching the code, reconcile with the reader's
`>= FN_REFLEN` (see finding 07).
