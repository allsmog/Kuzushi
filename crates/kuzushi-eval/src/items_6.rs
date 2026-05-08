use super::prelude::*;
use super::*;

pub(crate) fn cwes_match(finding_cwes: &[String], oracle_cwes: &[String]) -> bool {
    if oracle_cwes.is_empty() {
        return true; // oracle is permissive
    }
    if finding_cwes.is_empty() {
        return false; // oracle wants a CWE; finding has none
    }
    finding_cwes
        .iter()
        .any(|f| oracle_cwes.iter().any(|o| eq_ignore_case(f, o)))
}

pub(crate) fn cwe_match_or_no_oracle_cwe(finding_cwes: &[String], oracle_cwes: &[String]) -> bool {
    oracle_cwes.is_empty() || cwes_match(finding_cwes, oracle_cwes)
}

pub(crate) fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

pub(crate) fn line_in_oracle_range(line: u32, e: &OracleEntry) -> bool {
    e.line_start > 0 && e.line_end >= e.line_start && line >= e.line_start && line <= e.line_end
}
