# MariaDB/server findings catalog

Target: `MariaDB/server` HEAD `96b3dd0c` (fetched 2026-05-07).
Discovery: kuzushi (`allsmog/kuzushi`, branch `claude/test-kuzushi-oauth-mariadb-XTwVc`)
+ Anthropic Claude (model: `claude-opus-4-7`).
Verification: each finding below was independently checked by reading the
cited file at the cited line range. Lines numbers and source quotes are
ground-truth from the cited commit; the model's role was a pointer at
where to look.

## Layout

```
mariadb/
├── README.md         ← this file (index, status legend, promotion checklist)
├── verified/         ← VERIFIED findings, one numbered file each (01-NN)
└── unverified/       ← agent-surfaced hypotheses that were checked
                       and did NOT hold; kept as REJECTED-Q##-*.md so
                       future audits can see the reasoning.
```

## Status legend

- **VERIFIED** — source quoted, claim holds, file/line references match.
- **VERIFIED-PARTIAL** — claim holds at the source level but practical
  impact requires verification I haven't done (typically: no built ASan
  PoC, or the threat-model assumption needs checking).
- **REJECTED** — agent claim does not match source on inspection.

## Index — VERIFIED (`verified/`)

### Submission-grade (filed in `/home/user/mariadb-disclosures/`)

| # | sev | file | rule |
|---|---|---|---|
| 01 | medium / high (DoS) | `sql/proxy_protocol.cc:207` | proxy v1 one-byte stack OOB write |
| 02 | medium / high (info-leak) | `sql/proxy_protocol.cc:220` | proxy v2 trailer-length inverted shift → uninit-stack disclosure |
| 03 | high | `extra/mariabackup/backup_copy.cc:1953-1982` | mariabackup `--decompress` shell command injection via filename |
| 04 | critical | `client/mysqlbinlog-engine.cc:744-1058` | binlog page-size shift heap overflow |
| 05 | medium (info-leak) | `client/mysqlbinlog-engine.cc:445-505` | 16-bit `chunk_len` parsed without per-page bounds check before `memcpy` |
| 06 | high | `extra/mariabackup/xbstream_write.cc:333-360` | release-build stack overflow on long paths |
| 07 | low (parser) | `xbstream_write.cc:96` ↔ `xbstream_read.cc:148` | writer/reader off-by-one |
| 08 | low | `extra/readline/histfile.c:168-238` | `chars_read` int-narrows `read()`'s `ssize_t` |

### Catalog only — not yet submitted

| # | sev | file | rule |
|---|---|---|---|
| 09 | high | `extra/mariabackup/xbstream_read.cc:218` | `chunk->length + 1` integer overflow + no-op `> SIZE_T_MAX` check |
| 10 | medium | `storage/innobase/include/mtr0log.h:217` | `mtr_t::memset` repeating-string overload increments by `len` instead of `size` |
| 11 | high | `storage/innobase/log/log0recv.cc` (`mtr_t::parse_length`) | `MLOG_DECODE_ERROR` only ut_ad-checked; propagates `0xFFFFFFFF` as record length |
| 12 | high | `storage/innobase/log/log0recv.cc` (`mlog_decode_varint_length`) | `0xff` prefix path returns `255` instead of error sentinel |
| 13 | high | `storage/innobase/fil/fil0crypt.cc` (`fil_crypt_parse`) | redo-log apply trusts record without length / IV checks |
| 14 | medium | `storage/innobase/log/log0recv.cc` (`log_phys_t::undo_append`) | `free + len + 6` size_t arithmetic can wrap |
| 15 | low | `storage/innobase/log/log0recv.cc` (`log_phys_t::end()`) | debug-only NUL terminator at record end |
| 16 | medium | `storage/innobase/log/log0recv.cc` (`log_phys_t::append`) | `memcpy` runs before `uint16_t` truncation; mismatched allocation+write |
| 17 | high | `storage/innobase/fil/fil0pagecompress.cc` (`fil_page_decompress_for_full_crc32`) | `size_t` underflow on `buf[size-5]` LSB adjustment when `size = 0` |
| 18 | medium | `storage/innobase/fil/fil0pagecompress.cc` (`fil_page_decompress_low`) | `static_cast<int>(actual_size)` narrowing into `LZ4_decompress_safe` |
| 19 | medium | `storage/innobase/fil/fil0pagecompress.cc` (`fil_page_decompress_low`) | helper trusts `actual_size`; only the non-full-CRC32 caller validates |
| 20 | low | `storage/innobase/include/mtr0log.h` (bulk helpers) | `memset`/`memcpy`/`memmove` gate page bounds with `ut_ad` only |
| 21 | medium | `storage/innobase/fil/fil0crypt.cc` (`fil_space_read_crypt_data`) | encryption-offset not bounded to physical page size |
| 22 | low | `storage/innobase/trx/trx0rseg.cc:183` | XID lengths read from page without bound check (mitigated by `wsrep_is_wsrep_xid` gate) |

## Index — REJECTED (`unverified/`)

| ref | reason |
|---|---|
| `REJECTED-Q10-block-size-alignment-write.md` | `block_size` clamped at 4096 by `fil_space_get_block_size`, so alignment cannot exceed `srv_page_size`. |
| `REJECTED-Q13-fsp0file-read-first-page-flags.md` | `read_first_page_flags` is gated on `err == DB_SUCCESS`; partial-read paths exit with `DB_IO_ERROR`. |
| `REJECTED-Q15-base64-decode-mark-rewind.md` | `decoder.mark` is bounded to ≤ 2 by the state machine; `*d++` triple advance always exceeds the rewind. |

## Cross-finding bundles for disclosure

- **Redo-log apply hardening** (findings 11, 12, 13, 14, 15, 16, 21).
  Single advisory covering recv parse / log_phys_t / fil_crypt_parse
  / encryption-offset family. Multi-CVE candidate.
- **page_compressed format hardening** (findings 17, 18, 19). Single
  advisory; finding 17 is the underflow primitive, 18/19 close the
  funnel.
- **Defense-in-depth notes** (findings 20, 22). Don't file standalone;
  reference from the corresponding apply-path or trx advisories.
- **mtr_t memset stride** (finding 10). File standalone with the
  caveat that crash recovery normalises.

## Recommended next actions

1. Disclosure docs for findings 09 and 10 (drafted-pending).
2. Bundle redo-log apply hardening (findings 11-16) as a single
   advisory; share with MariaDB security ML.
3. Bundle page_compressed hardening (findings 17-19); reference 21
   if InnoDB security wants the broader format-bounds pass.

## How to add a finding

Each verified finding gets a markdown file in `verified/`:
`NN-short-slug.md`. Standard fields:

```markdown
# NN — <short title>

- **Status**: VERIFIED / VERIFIED-PARTIAL
- **Severity**: critical / high / medium / low
- **File**: `path/to/file.cc`
- **Line(s)**: 123-145
- **CWE**: CWE-787 / etc.
- **Discovered by**: tool name (carlini-threat-hunt:run / systems-hunt:systems-hunt / variant:hunt / ndiff:hunt-variants)
- **Disclosure**: filed (path) / planned / not filed

## Summary
One paragraph.

## Source quote
```c
// verbatim from MariaDB at <commit>
```

## Verification notes
What I confirmed by reading the source and what's still pending.

## Suggested fix
Concrete code-change suggestion.

## Disclosure plan
What advisory bundle, severity, etc.
```

For rejected hypotheses, drop a `REJECTED-Q##-*.md` in `unverified/`
that quotes the source and explains why the agent's claim does not
hold.
