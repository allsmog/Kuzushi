use crate::{
    cwe_match_or_no_oracle_cwe, OracleEntry, PM_LINES_FUNCTION_FALLBACK, PM_LINES_PRIMARY,
};

#[derive(Copy, Clone, Debug)]
pub(crate) enum Tolerance {
    ExactLine,
    PmLines,
    Function,
    FileOnly,
}

impl Tolerance {
    pub(crate) fn priority(self) -> u8 {
        match self {
            Self::ExactLine => 4,
            Self::PmLines => 3,
            Self::Function => 2,
            Self::FileOnly => 1,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ExactLine => "exact_line",
            Self::PmLines => "pm_lines",
            Self::Function => "function",
            Self::FileOnly => "file_only",
        }
    }

    pub(crate) fn count_start_index(self) -> usize {
        match self {
            Self::ExactLine => 0,
            Self::PmLines => 1,
            Self::Function => 2,
            Self::FileOnly => 3,
        }
    }
}

pub(crate) fn tolerance_for_match(
    finding_line: u32,
    delta: i64,
    finding_cwes: &[String],
    entry: &OracleEntry,
    cwe_match: bool,
) -> Tolerance {
    let abs_delta = delta.abs();
    if entry.line_start == 0 {
        Tolerance::FileOnly
    } else if abs_delta == 0 && cwe_match_or_no_oracle_cwe(finding_cwes, &entry.cwe) {
        Tolerance::ExactLine
    } else if abs_delta <= PM_LINES_PRIMARY && cwe_match {
        Tolerance::PmLines
    } else if abs_delta <= PM_LINES_FUNCTION_FALLBACK && cwe_match {
        Tolerance::Function
    } else if line_in_oracle_range(finding_line, entry) {
        Tolerance::Function
    } else {
        Tolerance::FileOnly
    }
}

pub(crate) fn line_in_oracle_range(line: u32, entry: &OracleEntry) -> bool {
    entry.line_start > 0
        && entry.line_end >= entry.line_start
        && line >= entry.line_start
        && line <= entry.line_end
}
