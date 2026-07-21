//! Impact-derived severity for imported fuzz findings.
//!
//! A crash whose replay shows a write/exec primitive is the
//! attacker-controlled-memory-write shape and imports HIGH; everything else
//! (reads, unknown primitives, unimpacted crashes) is capped at MEDIUM —
//! read OOBs stay findings (egress-channel leads) but must not crowd the
//! review queue above proven write primitives.

use crate::findings::Severity;

pub fn fuzz_severity(primitive: Option<&str>, write_evidence: bool) -> Severity {
    match primitive.map(str::trim) {
        Some("write") | Some("exec") => Severity::High,
        _ if write_evidence => Severity::High,
        _ => Severity::Medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_and_exec_primitives_import_high() {
        assert_eq!(fuzz_severity(Some("write"), false), Severity::High);
        assert_eq!(fuzz_severity(Some("exec"), false), Severity::High);
        assert_eq!(fuzz_severity(Some("read"), true), Severity::High);
    }

    #[test]
    fn everything_else_is_capped_at_medium() {
        assert_eq!(fuzz_severity(Some("read"), false), Severity::Medium);
        assert_eq!(fuzz_severity(Some("unknown"), false), Severity::Medium);
        assert_eq!(fuzz_severity(None, false), Severity::Medium);
    }
}
