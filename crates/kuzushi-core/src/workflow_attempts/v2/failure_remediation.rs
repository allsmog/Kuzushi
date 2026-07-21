//! Maps a failed run's terminal summary onto a drafted operator remediation.
//!
//! The phase receipt is an operator decision surface: "inspect the evidence"
//! is only the right NEXT action when the failure class is unknown. For the
//! classes we can recognize from the terminal summary, the receipt carries
//! the concrete way out instead.

/// A recognized failure class, split so call sites can compose the ask:
/// `cause` states what went wrong, `action` states the way out (with no
/// trailing "retry" — the continuation kind already says that).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FailureRemediation {
    pub(super) cause: &'static str,
    pub(super) action: &'static str,
}

const FAILURE_REMEDIATIONS: &[(&[&str], FailureRemediation)] = &[
    (
        &[
            "coverage limit",
            "entry cap",
            "content-inspection cap",
            "walk cap",
        ],
        FailureRemediation {
            cause: "a coverage cap was hit",
            action: "scope the target (or audit via shards)",
        },
    ),
    (
        &["read limit", "persistence failed"],
        FailureRemediation {
            cause: "result persistence hit a storage limit",
            action: "narrow the target scope",
        },
    ),
    (
        &["budget exceeded", "budget exhausted", "cost cap"],
        FailureRemediation {
            cause: "the run hit its budget cap",
            action: "raise the budget or narrow scope",
        },
    ),
    (
        &[
            "missing authentication credential",
            "unauthorized",
            "invalid api key",
        ],
        FailureRemediation {
            cause: "authentication failed",
            action: "repair credentials via auth",
        },
    ),
    (
        &["timed out", "timeout"],
        FailureRemediation {
            cause: "the run timed out",
            action: "raise the timeout or narrow scope",
        },
    ),
];

/// Returns a drafted remediation for a recognized failure class, or `None`
/// when the summary matches nothing we can act on.
pub(super) fn remediation_for(summary: &str) -> Option<FailureRemediation> {
    let summary = summary.to_lowercase();
    FAILURE_REMEDIATIONS
        .iter()
        .find(|(patterns, _)| patterns.iter().any(|pattern| summary.contains(pattern)))
        .map(|(_, remediation)| *remediation)
}

#[cfg(test)]
mod tests {
    use super::remediation_for;

    #[test]
    fn recognizes_coverage_cap_failures_case_insensitively() {
        let remediation =
            remediation_for("Context inventory exceeded the 100000-entry coverage limit")
                .expect("coverage cap is a recognized class");
        assert_eq!(remediation.cause, "a coverage cap was hit");
        assert_eq!(remediation.action, "scope the target (or audit via shards)");
    }

    #[test]
    fn recognizes_persistence_read_limit_failures() {
        let remediation = remediation_for(
            "run artifact persistence failed: CAS object declares 82751104 bytes above the 67108864-byte read limit",
        )
        .expect("read limit is a recognized class");
        assert_eq!(remediation.cause, "result persistence hit a storage limit");
    }

    #[test]
    fn first_matching_class_wins_over_later_patterns() {
        // "budget exhausted" and "timed out" both present: budget is listed first.
        let remediation = remediation_for("stream budget exhausted after run timed out")
            .expect("budget is a recognized class");
        assert_eq!(remediation.cause, "the run hit its budget cap");
    }

    #[test]
    fn unknown_failures_draft_nothing() {
        assert!(remediation_for("segfault in scanner worker").is_none());
    }
}
