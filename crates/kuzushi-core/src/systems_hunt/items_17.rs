use super::prelude::*;
use super::*;

pub(crate) fn classify_line(line: &str) -> Vec<(&'static str, &'static str, i64)> {
    let lower = line.to_ascii_lowercase();
    let mut signals = Vec::new();
    if contains_any(
        &lower,
        &[
            "packet", "parser", "parse", "decode", "frame", "segment", "recv", "rpc", "xdr",
            "header",
        ],
    ) {
        signals.push((
            "protocol-parser",
            "protocol parser or input framing signal",
            7,
        ));
    }
    if contains_any(
        &lower,
        &[
            "uint16", "u16", "usize", "size_t", "len", "length", "offset", "wrap", "overflow",
            "sentinel",
        ],
    ) {
        signals.push(("integer-boundary", "integer boundary or sentinel signal", 5));
    }
    if contains_any(
        &lower,
        &[
            "unsafe",
            "memcpy",
            "memmove",
            "strcpy",
            "copy_from",
            "from_raw_parts",
            "*mut",
            "*const",
        ],
    ) {
        signals.push(("unsafe-memory", "unsafe memory operation signal", 6));
    }
    if contains_any(
        &lower,
        &[
            "shared",
            "splice",
            "pipe_buffer",
            "iov_iter",
            "scatterlist",
            "page",
            "alias",
        ],
    ) {
        signals.push((
            "resource-provenance",
            "shared resource provenance signal",
            8,
        ));
    }
    if contains_any(
        &lower,
        &[
            "checked_",
            "saturating_",
            "validate",
            "guard",
            "assert",
            "bounds",
        ],
    ) {
        signals.push(("hardening", "hardening or guard signal", 2));
    }
    signals
}

pub(crate) fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

pub(crate) fn infer_kind(file_path: &str, line: &str) -> String {
    let raw = format!("{file_path}\n{line}").to_ascii_lowercase();
    if contains_any(&raw, &["rpc", "xdr", "nfs"]) {
        "rpc-handler".to_string()
    } else if contains_any(&raw, &["codec", "decode", "frame", "h264", "parser"]) {
        "codec-parser".to_string()
    } else if contains_any(&raw, &["hypervisor", "guest", "virt", "vmexit"]) {
        "hypervisor-boundary".to_string()
    } else if contains_any(
        &raw,
        &["shared", "splice", "pipe", "iov_iter", "scatterlist"],
    ) {
        "resource-provenance".to_string()
    } else if contains_any(&raw, &["unsafe", "memcpy", "*mut", "*const"]) {
        "unsafe-region".to_string()
    } else {
        "protocol-parser".to_string()
    }
}

pub(crate) fn attacker_fields(line: &str) -> Vec<String> {
    let lower = line.to_ascii_lowercase();
    let mut out = Vec::new();
    for candidate in [
        "len", "length", "size", "offset", "packet", "frame", "count",
    ] {
        if lower.contains(candidate) {
            out.push(candidate.to_string());
        }
    }
    out
}
