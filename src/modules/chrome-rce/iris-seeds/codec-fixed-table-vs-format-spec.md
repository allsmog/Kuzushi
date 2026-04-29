# IRIS seed — codec fixed-size lookup table vs format-spec mismatch (CVE-2023-4863)

You are running an IRIS-style CodeQL loop. Your job is to author CodeQL queries that find a specific class of memory-safety bug in image / video codec decoders, anchored to a verified historical CVE.

## Anchor CVE

**CVE-2023-4863 (libwebp `BuildHuffmanTable`)** — September 2023, ITW, weaponised for NSO Pegasus delivery, fixed in libwebp 1.3.2 (and re-issued upstream as CVE-2023-5129).

## The vulnerable code shape

The libwebp lossless decoder allocates a Huffman lookup table sized for the common case:

```c
// caller:
HuffmanCode root_table[1 << LENGTHS_TABLE_BITS];   // LENGTHS_TABLE_BITS = 8 → 256 entries
BuildHuffmanTable(root_table, ...);

// inside BuildHuffmanTable (huffman_utils.c, pre-fix):
for (; count[len] > 0; --count[len]) {
  if ((key & mask) != low) {
    table += table_size;          // pointer walks past root_table[]
    table_size = 1 << table_bits;
    total_size += table_size;
  }
  ReplicateValue(&table[key >> root_bits], step, table_size, code);  // OOB write
}
```

The lossless format specification allows code lengths up to **15 bits**. When a code longer than 8 bits appears, the decoder needs a **second-level table** reached via pointer arithmetic on `table`. Nothing in the loop compares `table` (or `total_size`) against the caller's allocated size. Crafted input with many long codes pushes `total_size` past 256 and `ReplicateValue` writes onto adjacent heap memory — heap corruption with attacker control over the values written.

The fix introduces a `HuffmanTables` struct that mallocs a **fresh segment** when capacity would be exceeded, replacing the implicit pointer arithmetic with an explicit segmented allocator.

## The bug class

Generalising past libwebp: **a decoder allocates a fixed-size lookup table sized from a compile-time `*_TABLE_BITS` macro, but the format spec allows codes longer than that bit-width, and the decoder uses pointer arithmetic on the table to write into "extension" entries without a bounds check against the caller's allocation.**

This pattern shows up across image/video codecs:
- libwebp (CVE-2023-4863) — the anchor.
- libvpx Huffman / range-decoder tables (multiple non-ITW bugs).
- libaom / dav1d analogous code paths.
- Any custom in-Chromium Huffman/arithmetic-coder decoder.

## Your job

Write CodeQL queries that find this pattern. Iterate until queries compile cleanly and return at least one result on the target codebase. Specifically:

### Query A — fixed-size lookup table

Find function-scope or file-scope `<T> name[1 << <CONST>]` array declarations in **decoder source files** (paths matching `third_party/{libwebp,libvpx,libaom,dav1d,libavif,libpng}/**` or `media/**`). The constant should be a `*_TABLE_BITS`-style macro or a small integer literal (≤ 12). Capture:
- the array variable
- the dimension constant (the `<CONST>` in `1 << <CONST>`)

### Query B — pointer arithmetic on the array

Find binary expressions of the form `<array> += <expr>` or `++<array>` or `<array>++` where `<array>` is a metavariable bound by Query A's array name. Capture:
- the writing site `*<array>`, `<array>[<i>]`, or `&<array>[<i>]` that follows
- the loop or function scope of the arithmetic

### Query C — the unsafe combination

Use TaintTracking to model:
- **Source**: any function parameter representing input data — `bytes`, `data`, `len`, `count[]`, format-header struct fields, etc. Heuristic: any parameter whose name matches `/^(buf|data|bytes|len|size|count|input)/i`.
- **Sink**: a **write through `<array>`** (case (b)) inside a loop where `<array>` is the metavariable bound by Query A.
- **Sanitizer**: comparisons of the form `<array> < <end>`, `<count> < <bound>`, or `<total_size> <= <max>` that bound the writes.

Flag any flow whose taint path reaches a sink WITHOUT passing through a sanitizer guard.

### Query D — format-spec-vs-allocation mismatch (advanced, optional)

Find `*_TABLE_BITS`-style constants used in array dimensions. Cross-reference with the codec's published spec (Huffman bit-length max, AV1 OBU max sizes, PNG IDAT chunk max, etc.). If the constant is **smaller** than the spec maximum, surface the file as needing review. This is a heuristic — write it to flag candidates rather than confirm bugs.

## Iteration loop instructions

When CodeQL compilation fails:
- Read the error from the `codeql query run` output.
- The most common errors with C/C++ codeql are missing imports — `import semmle.code.cpp.dataflow.TaintTracking`, `import semmle.code.cpp.controlflow.SubBasicBlocks`, etc.
- For range analysis on the dimension constant, use `import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis` and `getValue()` on integer literals.
- For pointer arithmetic recognition: a `+= <expr>` on a pointer-typed local is `AssignAddExpr` on a `PointerType` `LocalScopeVariable`.

## Useful CodeQL libraries

```ql
import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.controlflow.SubBasicBlocks
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
```

## Honest caveats

This bug class is **hard to confirm purely statically**. The actual exploit on libwebp required:
1. The loop emitting more `ReplicateValue` writes than the root-table capacity allowed.
2. The caller allocating `1 << 8` and the decoder accepting codes up to `1 << 15`.

A CodeQL query can identify *candidate* code shapes but cannot fully reason about format-spec semantics. Flag candidates with `needs_review` confidence and surface the format-spec line in the rationale so a human reviewer can quickly compare.

The **negative class** is also important: many decoders DO bound their writes correctly (e.g. they pass an `end` pointer alongside `<array>` and check `<array> < end` on every iteration). Don't flag those.

## Output

For each candidate, the IRIS loop should produce a structured finding with:

- `cveAnchor`: "CVE-2023-4863"
- `file`, `function`, `line`, `evidenceLines` (the loop body)
- `verdict`: `tp` | `fp` | `needs_review`
- `confidence`: 0..1 (lean conservative — this rule has high FP cost)
- `formatSpecCheck`: one sentence on whether the rule could read the codec's format spec to confirm the bit-length mismatch (note: this requires reading external docs the LLM doesn't have)
- `mitigation`: 1-2 sentences on the simplest fix (introduce a segmented allocator + capacity check, mirror the libwebp 1.3.2 patch).

Cite CVE-2023-4863 in the finding's rationale and link to the libwebp 1.3.2 patch shape.
