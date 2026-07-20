use super::*;

/// Native memory-safety pack: the bug classes that dominate C/C++
/// parser and backup/dataplane codebases. Signals are substring
/// patterns against call expressions, same contract as the rest of
/// the catalog.

/// A wider integer (often an attacker-controlled 64-bit length or
/// offset) narrowed into a 32-bit value before an allocation, copy,
/// or seek — the truncated value then under-sizes a buffer or wraps a
/// bounds check.
pub(super) const NUMERIC_TRUNCATION: TaintIrisNextCatalogEntry = TaintIrisNextCatalogEntry {
    cwe: "CWE-197",
    name: "Numeric Truncation",
    taint_class: "numeric-truncation",
    languages: TAINT_IRIS_NEXT_NATIVE,
    source_signals: &[
        "int64_t",
        "uint64_t",
        "size_t",
        "file_size",
        "content_length",
        "ntohll",
    ],
    sink_signals: &[
        "static_cast<int",
        "static_cast<uint32",
        "(int32_t)",
        "(uint32_t)",
        "(int)",
        "narrow",
    ],
    sanitizer_signals: &[
        "numeric_limits",
        "INT32_MAX",
        "INT_MAX",
        "checked_cast",
        "narrow_cast",
    ],
    structural_queries: &[
        "static_cast<int",
        "(int32_t)",
        "(uint32_t)",
        "narrow_cast",
        "numeric_limits",
    ],
};

/// Allocation sized from one expression while the copy into it is
/// sized from another (alloc-vs-copy mismatch), or a raw write sized
/// by untrusted input.
pub(super) const OUT_OF_BOUNDS_WRITE: TaintIrisNextCatalogEntry = TaintIrisNextCatalogEntry {
    cwe: "CWE-787",
    name: "Out-of-bounds Write",
    taint_class: "out-of-bounds-write",
    languages: TAINT_IRIS_NEXT_NATIVE,
    source_signals: &["recv(", "fread(", "ntohl(", "ntohs(", "deserialize", "parse"],
    sink_signals: &[
        "memcpy(",
        "memmove(",
        "memset(",
        "strcpy(",
        "sprintf(",
        "alloca(",
    ],
    sanitizer_signals: &["sizeof(", "CHECK_LE", "bounds check", "resize(", "reserve("],
    structural_queries: &["memcpy(", "memmove(", "strcpy(", "sprintf(", "alloca("],
};

/// Untrusted offset/index/length applied to a buffer before the read
/// is bounds-checked — classic parser OOB read that leaks adjacent
/// heap into an output or egress channel.
pub(super) const OUT_OF_BOUNDS_READ: TaintIrisNextCatalogEntry = TaintIrisNextCatalogEntry {
    cwe: "CWE-125",
    name: "Out-of-bounds Read",
    taint_class: "out-of-bounds-read",
    languages: TAINT_IRIS_NEXT_NATIVE,
    source_signals: &["offset", "ntohl(", "header", "index", "chunk length"],
    sink_signals: &[
        "data() +",
        "buf +",
        "reinterpret_cast<",
        "[offset",
        "memcmp(",
    ],
    sanitizer_signals: &["size() <", "< size()", "CHECK_LT", ".at(", "bounds"],
    structural_queries: &[
        "reinterpret_cast<",
        "data() +",
        "[offset",
        "memcmp(",
        ".at(",
    ],
};
