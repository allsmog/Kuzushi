# 03 — `mariabackup --decompress` shell command injection via filename

- **Status**: VERIFIED
- **Severity**: high (priv-esc to `mysql` / `root` on the decompressing host)
- **File**: `extra/mariabackup/backup_copy.cc`
- **Line(s)**: 1953-1982 (`decrypt_decompress_file`)
- **CWE**: CWE-78 (OS Command Injection), CWE-77, optionally CWE-88
- **Discovered by**: `carlini-threat-hunt:run`, fingerprint `aeccdfcc1c4338ea`
- **Disclosure**: filed at `/home/user/mariadb-disclosures/3-mariabackup-decompress-cmdi.txt`

## Summary

`decrypt_decompress_file()` builds a shell command line by concatenating
attacker-controlled filenames into a `cat <filepath> | qpress -dio >
<dest_filepath>` pipeline and executes it via `system()`. Both
interpolations are **unquoted**. The caller iterates files via
`datadir_iter_new(".")` under `--target-dir`, so any file with shell
metacharacters in its name (e.g. `$(touch /tmp/PWNED)a.qp`) gets executed
as the user running mariabackup — typically the privileged `mysql`
account or root. `dest_filepath` is `strdup(filepath)` with `.qp`
stripped, so it carries the same metacharacters.

## Source quote

```c
// backup_copy.cc
1953: bool decrypt_decompress_file(const char *filepath, uint thread_n) {
1956:   std::stringstream cmd, message;
1957:   char *dest_filepath = strdup(filepath);
1960:   cmd << IF_WIN("type ","cat ") << filepath;     // unquoted
1964:     cmd << " | qpress -dio ";
1965:     dest_filepath[strlen(dest_filepath) - 3] = 0;
1973:   cmd << " > " << dest_filepath;                  // unquoted
1982:   if (system(cmd.str().c_str()) != 0) { ... }
```

## Verification notes

Read end-to-end. Caller at `backup_copy.cc:2015` is
`decrypt_decompress_file(node.filepath, ...)`, with `node.filepath` from
`datadir_iter_new(".", false)` (line 2048). PoC harness at
`/home/user/repros/repro3_mariabackup_cmdi.c` confirms shell evaluates
`$(touch /tmp/PWNED-3)a.qp`. xbstream extractor (`xbstream.cc:mode_extract
→ local_open`) only enforces `MY_RELATIVE_PATH` + `O_NOFOLLOW` —
shell-metachar names pass through.

## Suggested fix

Drop `system()`, fork+exec qpress directly with argv (eliminates shell
parsing entirely). See disclosure doc for the rewrite.
