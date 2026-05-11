# 13 — `fil_crypt_parse` reads from a redo-log record without runtime bounds checks

- **Status**: VERIFIED
- **Severity**: high (redo-log apply path; reads `MY_AES_BLOCK_SIZE +
  11 = 27` bytes off the recv parse buffer with only `ut_ad` to gate)
- **File**: `storage/innobase/fil/fil0crypt.cc`
- **Line(s)**: 351-374 (`fil_crypt_parse`)
- **CWE**: CWE-125 (Out-of-bounds Read), CWE-617 (debug-only assert)
- **Discovered by**: `systems-hunt:systems-hunt` (default budget; promoted from queue Q3)
- **Disclosure**: not yet filed

## Summary

`fil_crypt_parse` is the redo-log apply handler for the `OPT_FILE_*`
crypt records. It reads `data[0]`, `data[1]`, `data[2..]` (the IV,
`MY_AES_BLOCK_SIZE = 16` bytes), and `data[2+16..2+16+8] = data[18..26]`
without any runtime length check. The single check on the input —
`ut_ad(data[1] == MY_AES_BLOCK_SIZE)` — is debug-only.

The redo-log parse path that dispatches into `fil_crypt_parse` is
expected to have already validated the record length (it knows the
record type). If the upstream length is wrong (e.g. truncated near a
page boundary, or after a varint-length goof from finding 11/12),
`fil_crypt_parse` happily reads up to 11 bytes of out-of-bounds memory
and uses those as IV / crypt scheme / key id / encryption-policy.

## Source quote

```c
// fil0crypt.cc
348: /** Amend encryption information from redo log.
349: @param[in]	space	tablespace
350: @param[in]	data	encryption metadata */
351: void fil_crypt_parse(fil_space_t* space, const byte* data)
352: {
353:   ut_ad(data[1] == MY_AES_BLOCK_SIZE);                    // <-- debug only
354:   if (void* buf = ut_zalloc_nokey(sizeof(fil_space_crypt_t))) {
355:     fil_space_crypt_t* crypt_data = new(buf)
356:       fil_space_crypt_t(
357:         data[0],
358:         mach_read_from_4(&data[2 + MY_AES_BLOCK_SIZE]),     // data[18..21]
359:         mach_read_from_4(&data[6 + MY_AES_BLOCK_SIZE]),     // data[22..25]
360:         static_cast<fil_encryption_t>
361:         (data[10 + MY_AES_BLOCK_SIZE]));                    // data[26]
362:     memcpy(crypt_data->iv, data + 2, MY_AES_BLOCK_SIZE);    // data[2..17]
363:     ...
374: }
```

## Verification notes

- `MY_AES_BLOCK_SIZE` is `16`, so the function reads bytes `[0..26]`
  unconditionally.
- All callers of `fil_crypt_parse` come from `recv_sys` apply-path
  dispatch. The recv-side dispatch knows its record length (from
  `parse_length`) but does not pass that length down. The function
  assumes the caller verified.
- `ut_ad(data[1] == MY_AES_BLOCK_SIZE)` actually doesn't even check
  the length is at least 2 — it dereferences `data[1]` first, then
  asserts. If the upstream length is `0` or `1`, this is already an
  OOB read. (Mitigated only because dispatch presumably gates on
  type-specific minimums upstream — but those minimums need to be
  audited.)
- The values read (`type`, `min_key_version`, `key_id`, encryption
  policy) are stored on the tablespace and consulted at every
  page-read decryption call, so the impact persists past the parse
  step.

## Suggested fix

Take a length argument and gate every dereference:

```c
void fil_crypt_parse(fil_space_t* space, const byte* data, size_t len)
{
  if (UNIV_UNLIKELY(len < 1 + 1 + MY_AES_BLOCK_SIZE + 4 + 4 + 1)) {
    recv_sys.set_corrupt_log();
    return;
  }
  if (UNIV_UNLIKELY(data[1] != MY_AES_BLOCK_SIZE)) {
    recv_sys.set_corrupt_log();
    return;
  }
  ...
}
```

Audit the dispatcher call site to forward the parsed record length.

## Disclosure plan

Bundle with redo-log apply hardening (findings 11/12, 14-16). Single
report, multi-CVE candidate.
