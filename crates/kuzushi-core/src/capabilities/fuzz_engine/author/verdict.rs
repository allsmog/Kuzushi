//! Deterministic authoring verdicts.
//!
//! The model never grades itself: after the tool loop ends, the built
//! binary on disk and one Rust-driven smoke run decide whether a harness
//! was authored. A sanitizer crash during smoke is a success with a bonus
//! (the harness already found something).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorVerdict {
    /// Fuzzer built and the smoke run executed cleanly.
    Authored,
    /// Fuzzer built and the smoke run already hit a sanitizer report.
    AuthoredWithCrash,
    /// No usable binary, or the binary dies without a sanitizer report.
    Failed,
    /// The per-run budget ran out before this target got a session.
    BudgetExhausted,
}

impl AuthorVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authored => "authored",
            Self::AuthoredWithCrash => "authored-with-crash",
            Self::Failed => "failed",
            Self::BudgetExhausted => "budget-exhausted",
        }
    }

    pub fn is_authored(self) -> bool {
        matches!(self, Self::Authored | Self::AuthoredWithCrash)
    }
}

#[derive(Debug, Clone)]
pub struct SmokeResult {
    pub exit_ok: bool,
    pub crashed: bool,
    pub excerpt: String,
}

const SANITIZER_MARKERS: [&str; 4] = [
    "ERROR: AddressSanitizer",
    "ERROR: LeakSanitizer",
    "UndefinedBehaviorSanitizer",
    "DEADLY SIGNAL",
];

pub fn smoke_result(exit_ok: bool, combined_output: &str) -> SmokeResult {
    let crashed = SANITIZER_MARKERS
        .iter()
        .any(|marker| combined_output.contains(marker));
    SmokeResult {
        exit_ok,
        crashed,
        excerpt: tail_excerpt(combined_output, 2000),
    }
}

pub fn author_verdict(fuzzer_built: bool, smoke: Option<&SmokeResult>) -> AuthorVerdict {
    if !fuzzer_built {
        return AuthorVerdict::Failed;
    }
    match smoke {
        Some(result) if result.crashed => AuthorVerdict::AuthoredWithCrash,
        Some(result) if result.exit_ok => AuthorVerdict::Authored,
        _ => AuthorVerdict::Failed,
    }
}

pub fn tail_excerpt(text: &str, max_chars: usize) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= max_chars {
        return trimmed.to_string();
    }
    let tail: String = trimmed
        .chars()
        .rev()
        .take(max_chars)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("…{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_table_is_deterministic() {
        let clean = smoke_result(true, "Done 256 runs");
        let crash = smoke_result(false, "==1==ERROR: AddressSanitizer: heap-buffer-overflow");
        let broken = smoke_result(false, "fuzzer: command not found");

        assert_eq!(author_verdict(false, Some(&clean)), AuthorVerdict::Failed);
        assert_eq!(author_verdict(true, None), AuthorVerdict::Failed);
        assert_eq!(author_verdict(true, Some(&clean)), AuthorVerdict::Authored);
        assert_eq!(
            author_verdict(true, Some(&crash)),
            AuthorVerdict::AuthoredWithCrash
        );
        assert_eq!(author_verdict(true, Some(&broken)), AuthorVerdict::Failed);
        assert!(AuthorVerdict::AuthoredWithCrash.is_authored());
    }

    #[test]
    fn smoke_crash_detection_reads_sanitizer_markers_not_exit_codes() {
        assert!(smoke_result(true, "libFuzzer: DEADLY SIGNAL").crashed);
        assert!(!smoke_result(false, "config error: missing seed dir").crashed);
    }

    #[test]
    fn tail_excerpt_keeps_the_end_of_long_output() {
        let long = format!("{}END", "x".repeat(5000));
        let excerpt = tail_excerpt(&long, 100);
        assert!(excerpt.ends_with("END"));
        assert!(excerpt.starts_with('…'));
        assert!(excerpt.chars().count() <= 101);
    }
}
