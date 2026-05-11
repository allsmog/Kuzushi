# 12 — `mlog_decode_varint_length` returns 255 for the `0xff` prefix instead of an error sentinel

- **Status**: VERIFIED
- **Severity**: high (compounds Q1/finding 11; lets attacker pass a
  255-byte synthetic varint through the recv parser)
- **File**: `storage/innobase/log/log0recv.cc`
- **Line(s)**: 78-93 (`mlog_decode_varint_length`). Bug at line 87.
- **CWE**: CWE-682 (Incorrect Calculation), CWE-704 (Incorrect Type
  Conversion)
- **Discovered by**: `systems-hunt:systems-hunt` (default budget; promoted from queue Q2)
- **Disclosure**: not yet filed

## Summary

The `__GNUC__` fast path uses a ternary that collapses both branches
into `uint8_t` via the implicit return-type conversion:

```c
return first == 0xff ? first : uint8_t(__builtin_clz(uint8_t(~first)) - 23);
```

When `first == 0xff` (`~first == 0` would otherwise crash `__builtin_clz`),
the function returns `0xff` cast to `uint8_t` — i.e. `255`. Callers
treat this as a valid varint *length* in bytes and advance `l += 255`
or `s = 255`, far past any real varint header (max 5 bytes per the
`MIN_5BYTE` design). Combined with finding 11 (`MLOG_DECODE_ERROR`
silently propagated), the recv parser walks 255 bytes of attacker-
controlled bytes as if they were a varint payload.

## Source quote

```c
// log0recv.cc
75: /** Decode the length of a variable-length encoded integer.
76: @param first  first byte of the encoded integer
77: @return the length, in bytes */
78: static uint8_t mlog_decode_varint_length(uint8_t first) noexcept
79: {
80: #if __cpp_lib_bitops >= 201907L /* C++20 #include <bit> */
81:   return 1 + std::countl_one(first);
82: #elif defined __GNUC__ && !defined __s390__ && !defined __m68k__ && !defined __riscv && !defined __sparc__
83:   /* Make use of the MIPS/POWER/ARM clz instruction or equivalent,
84:   such as the x86 BitScanReverse (bsr) or lzcnt (rep bsr).
85:   On s390x, 68k, RISC-V or SPARC, this would translate into a call
86:   to a library function. We prefer a simple loop in that case. */
87:   return first == 0xff ? first : uint8_t(__builtin_clz(uint8_t(~first)) - 23);
88: #else
89:   int len{1};
90:   for (int f{first}; f & 0x80; len++, f*= 2);
91:   return uint8_t(len);
92: #endif
93: }
```

## Verification notes

- The C++20 path (`std::countl_one`) returns `1 + countl_one(0xff) = 9`
  for the same input — also wrong, just a different wrong value. Both
  branches are buggy but in opposite directions.
- The `else` (loop) fallback also walks `for (int f{0xff}; f & 0x80;
  len++, f*= 2)` — `0xff & 0x80 == 0x80`, after `f*=2` we get `0x1FE
  & 0x80 == 0x80`, and so on. Loop terminates only when `f` overflows
  to a value with the top bit clear (depends on int width / undefined
  behavior). Effectively also yields a large length.
- The intent is clearly an "error" sentinel (the surrounding code has
  `MLOG_DECODE_ERROR` for exactly that purpose, line 73), but the
  function signature returns `uint8_t` so there's no room for a
  multi-byte sentinel. The correct fix is to special-case `0xff` as
  "treat the record as corrupt".

## Suggested fix

Reserve a length value the caller treats as failure (e.g. `0`),
consistent across all three branches:

```c
static uint8_t mlog_decode_varint_length(uint8_t first) noexcept
{
  if (UNIV_UNLIKELY(first == 0xff))
    return 0;                /* signals "invalid prefix" */
#if __cpp_lib_bitops >= 201907L
  return 1 + std::countl_one(first);
#elif defined __GNUC__ && !defined __s390__ && ...
  return uint8_t(__builtin_clz(uint8_t(~first)) - 23);
#else
  int len{1};
  for (int f{first}; f & 0x80; len++, f*= 2);
  return uint8_t(len);
#endif
}
```

Then have callers (`parse_length`, `mlog_decode_varint`) treat `0` as
"corrupt log".

## Disclosure plan

Bundle with finding 11 (Q1) as a single redo-log-parse hardening
report.
