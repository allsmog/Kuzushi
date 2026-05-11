# 11 — `mtr_t::parse_length` propagates `MLOG_DECODE_ERROR` sentinel as a record length in release builds

- **Status**: VERIFIED
- **Severity**: high (length-confusion in redo-log apply; downstream
  reads/writes of `*size` bytes can OOB the recv_sys parse buffer)
- **File**: `storage/innobase/log/log0recv.cc`
- **Line(s)**: 73 (`MLOG_DECODE_ERROR= ~0U`), 124-138 (`mtr_t::parse_length`). Bug at line 132.
- **CWE**: CWE-617 (Reachable Assertion → silent in release), CWE-191
  (Integer Underflow when `addlen + 15 - s` is computed with
  `addlen = 0xFFFFFFFF`), CWE-125/CWE-787 downstream.
- **Discovered by**: `systems-hunt:systems-hunt` (default budget; promoted from queue Q1)
- **Disclosure**: not yet filed

## Summary

`mlog_decode_varint` returns `MLOG_DECODE_ERROR` (`~0U`,
i.e. `0xFFFFFFFF`) on malformed varint input. `mtr_t::parse_length`
checks for that sentinel only with `ut_ad`, which is compiled out in
release builds. The `0xFFFFFFFF` value flows straight into the
record-length output `*size = addlen + 15 - s` (with `addlen ==
~0U`, that wraps to `0xFFFFFFFF + 15 - s = 14 - s` modulo 2^32 — a
near-SIZE_MAX value when `s ≤ 14`). Callers use `*size` to advance
parse cursors, perform `memcpy(recs, *size)`, etc., yielding OOB
reads/writes off the recv_sys parse buffer.

## Source quote

```c
// log0recv.cc
73: constexpr uint32_t MLOG_DECODE_ERROR= ~0U;

124: ATTRIBUTE_NOINLINE
125: const byte *mtr_t::parse_length(const byte *l, uint32_t *size) noexcept
126: {
127:   uint32_t s(*l++ & 0xf);
128:   if (!s)
129:   {
130:     s= mlog_decode_varint_length(*l);
131:     const uint32_t addlen{mlog_decode_varint(l)};
132:     ut_ad(addlen != MLOG_DECODE_ERROR);   // <-- debug-only
133:     l+= s;
134:     s= addlen + 15 - s;                    // wraps when addlen == ~0U
135:   }
136:   *size= s;
137:   return l;
138: }
```

## Verification notes

- `MLOG_DECODE_ERROR` is `~0U` (line 73), not a near-zero error code,
  so when interpreted as a record length it appears either as a wrap
  to near-zero (after `+15-s`) or as the literal `0xFFFFFFFF` if `s ==
  16`. Either is dangerous for callers that compute `next = l +
  *size`.
- `ut_ad` expands to nothing in release builds (`-DNDEBUG`).
- Reachable from any redo-log replay path (crash recovery, page-level
  log apply). Crafted ib_logfile bytes are sufficient — the redo log
  is parsed without authentication.
- Q2 (in this same file) compounds the impact: `mlog_decode_varint`'s
  `0xff` ternary path returns `255`, producing pseudo-valid lengths
  that bypass even partial sanity checks and feed Q1.

## Suggested fix

Promote the assertion to a runtime check that fails the recv parse:

```c
const uint32_t addlen{mlog_decode_varint(l)};
if (UNIV_UNLIKELY(addlen == MLOG_DECODE_ERROR)) {
  recv_sys.set_corrupt_log();
  return nullptr;
}
```

Audit every call site of `parse_length` to handle a `nullptr` /
sentinel-size return without dereferencing.

## Disclosure plan

Bundle with Q2 (varint length 255), Q4 (undo_append wrap), and the
log0recv `log_phys_t` family (Q5/Q6) as a single redo-log-apply
hardening report to MariaDB Security.
