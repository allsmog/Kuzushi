# 08 — `read_history_range`: `chars_read` declared `int`, narrows `read()` return

- **Status**: VERIFIED
- **Severity**: low (probably-upstream readline bug)
- **File**: `extra/readline/histfile.c`
- **Line(s)**: 168 (declaration), 205 + 214 (narrowing assignments), 238 (downstream consumer)
- **CWE**: CWE-197 (Numeric Truncation), CWE-681 (Incorrect Conversion)
- **Discovered by**: `systems-hunt:systems-hunt`
- **Disclosure**: filed at `/home/user/mariadb-disclosures/6-readline-histfile-narrowing.txt` (low — optional)

## Summary

`chars_read` is declared `int`; `read()` returns `ssize_t`; `file_size`
is `size_t`. For `~/.history` files larger than INT_MAX (≈2.1 GiB) the
two narrowings at lines 205 and 214 either truncate or wrap to negative
(triggering the spurious `if (chars_read < 0)` error path), corrupting
the parse-length used downstream at line 238 (`to = chars_read;`).

## Source quote

```c
168:  int file, current_line, chars_read;            // <-- int
171:  size_t file_size;                              // <-- size_t
205:  chars_read = file_size;                         // narrowing #1
214:  chars_read = read (file, buffer, file_size);    // narrowing #2
216:  if (chars_read < 0) ...                         // misclassifies on wrap
238:  to = chars_read;                                // corrupt length
```

## Verification notes

Read in source. The bug almost certainly exists upstream in GNU
readline; MariaDB's tree was imported in commit 88cebbdf (2014-10-01).
Trigger requires HISTFILE > 2.1 GiB. Practical impact is "history
silently dropped or partially loaded", not memory safety.

## Suggested fix

`int chars_read` → `ssize_t chars_read`. Widen the consumer at line 238
accordingly. Forward to readline maintainers if the patch lands.
